package lifecycle

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/kandev/kandev/internal/agent/agents"
	"github.com/kandev/kandev/internal/agent/remoteauth"
	agentctl "github.com/kandev/kandev/internal/agent/runtime/agentctl"
	agentctltypes "github.com/kandev/kandev/internal/agentctl/types"
)

const (
	agentctlFileTimeout = 30 * time.Second
	// agentctlFileMissingExit is the exit code the read command uses for a missing file.
	agentctlFileMissingExit = 3
	// agentctlExitMarker precedes the exit status a command prints before idling.
	agentctlExitMarker = "__kandev_exit="
)

type agentctlCommandClient interface {
	StartProcess(context.Context, agentctl.StartProcessRequest) (*agentctl.ProcessInfo, error)
	GetProcess(context.Context, string, bool) (*agentctl.ProcessInfo, error)
	StopProcess(context.Context, string) error
}

// agentctlFileUploader writes and reads files in a remote environment through
// agentctl processes. Paths and contents travel in the process environment, never
// in the command line, which agentctl exposes in process listings.
type agentctlFileUploader struct {
	client    agentctlCommandClient
	sessionID string
}

// run executes command and returns its output. agentctl forgets a process once it
// exits, so the command reports its exit status after a marker and idles until
// its output has been read and it is stopped.
func (u agentctlFileUploader) run(ctx context.Context, command string, env map[string]string) ([]byte, error) {
	process, err := u.client.StartProcess(ctx, agentctl.StartProcessRequest{
		SessionID: u.sessionID,
		Kind:      agentctltypes.ProcessKindCustom,
		Command:   "(\n" + command + "\n); printf '\\n" + agentctlExitMarker + "%s\\n' \"$?\"; exec sleep 60",
		Env:       env,
	})
	if err != nil {
		return nil, err
	}
	processID := process.ID
	defer func() { _ = u.client.StopProcess(context.WithoutCancel(ctx), processID) }()
	deadline := time.Now().Add(agentctlFileTimeout)
	for {
		if output, exitCode, done := agentctlCommandResult(process); done {
			if exitCode != 0 {
				return output, &agentctlProcessError{status: agentctltypes.ProcessStatusExited, exitCode: &exitCode}
			}
			return output, nil
		}
		if !time.Now().Before(deadline) {
			return nil, errors.New("agentctl command timed out")
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(100 * time.Millisecond):
		}
		if process, err = u.client.GetProcess(ctx, processID, true); err != nil {
			return nil, err
		}
	}
}

// agentctlCommandResult reports the output and exit status once the command has
// printed its exit marker.
func agentctlCommandResult(process *agentctl.ProcessInfo) ([]byte, int, bool) {
	var output strings.Builder
	for _, chunk := range process.Output {
		output.WriteString(chunk.Data)
	}
	text := output.String()
	index := strings.LastIndex(text, agentctlExitMarker)
	if index < 0 {
		return nil, 0, false
	}
	status := strings.TrimSpace(text[index+len(agentctlExitMarker):])
	exitCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, 0, false
	}
	return []byte(strings.TrimSuffix(text[:index], "\n")), exitCode, true
}

func (u agentctlFileUploader) WriteFile(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	_, err := u.run(ctx,
		`umask 077 && mkdir -p "$(dirname "$KANDEV_FILE_PATH")" && printf %s "$KANDEV_FILE_DATA" | base64 -d > "$KANDEV_FILE_PATH" && chmod "$KANDEV_FILE_MODE" "$KANDEV_FILE_PATH"`,
		map[string]string{
			"KANDEV_FILE_PATH": path,
			"KANDEV_FILE_DATA": base64.StdEncoding.EncodeToString(data),
			"KANDEV_FILE_MODE": fmt.Sprintf("%o", mode.Perm()),
		})
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (u agentctlFileUploader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	output, err := u.run(ctx,
		fmt.Sprintf(`[ -f "$KANDEV_FILE_PATH" ] || exit %d; base64 < "$KANDEV_FILE_PATH"`, agentctlFileMissingExit),
		map[string]string{"KANDEV_FILE_PATH": path})
	var processErr *agentctlProcessError
	if errors.As(err, &processErr) && processErr.exitCode != nil && *processErr.exitCode == agentctlFileMissingExit {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(output)), ""))
}

func (u agentctlFileUploader) homeDir(ctx context.Context, req *ExecutorCreateRequest) (string, error) {
	if override := strings.TrimSpace(getMetadataString(req.Metadata, MetadataKeyRemoteAuthHome)); override != "" {
		return override, nil
	}
	output, err := u.run(ctx, `printf %s "$HOME"`, nil)
	home := strings.TrimSpace(string(output))
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve remote home directory: %w", err)
	}
	return home, nil
}

// uploadPluginExecutorAgentCredentials copies the agent credential files and
// configuration bundles selected on the executor profile into the environment,
// and runs the setup scripts of selected environment-variable methods. Failures
// are logged and do not fail the launch, as for other remote executors.
func (r *PluginRemoteExecutor) uploadPluginExecutorAgentCredentials(ctx context.Context, client agentctlCommandClient, req *ExecutorCreateRequest) {
	if req.AgentConfig == nil {
		return
	}
	uploader := agentctlFileUploader{client: client, sessionID: req.SessionID}
	catalog := remoteauth.BuildCatalogForHost([]agents.Agent{req.AgentConfig}, runtime.GOOS, mustUserHome())
	methods, err := kubernetesSelectedCredentialMethods(req.Metadata, catalog)
	bundleIDs := selectedPortableConfigBundleIDs(req.Metadata)
	setupMethods := selectedSetupScriptMethods(catalog, req.Env)
	if err != nil || (len(methods) == 0 && len(bundleIDs) == 0 && len(setupMethods) == 0) {
		if err != nil {
			r.logger.Warn("plugin executor agent credentials are misconfigured", zap.Error(err))
		}
		return
	}
	home, err := uploader.homeDir(ctx, req)
	if err != nil {
		r.logger.Warn("plugin executor agent credentials were not uploaded", zap.Error(err))
		return
	}
	if err := UploadCredentialFiles(ctx, uploader, methods, home, r.logger); err != nil {
		r.logger.Warn("plugin executor agent credential upload failed", zap.Error(err))
	}
	reportPortableConfigWarnings(req.OnProgress,
		UploadPortableConfigBundles(ctx, uploader, req.AgentConfig, bundleIDs, home, r.logger))
	for _, method := range setupMethods {
		env := map[string]string{"HOME": home, method.EnvVar: req.Env[method.EnvVar]}
		if _, err := uploader.run(ctx, method.SetupScript, env); err != nil {
			r.logger.Warn("plugin executor agent auth setup script failed",
				zap.String("method_id", method.MethodID), zap.Error(err))
		}
	}
}

// selectedSetupScriptMethods returns the environment-variable methods whose
// variable was resolved for this launch and that declare a setup script.
func selectedSetupScriptMethods(catalog remoteauth.Catalog, env map[string]string) []remoteauth.Method {
	var methods []remoteauth.Method
	for _, spec := range catalog.Specs {
		for _, method := range spec.Methods {
			if method.Type == authMethodTypeEnv && method.EnvVar != "" && method.SetupScript != "" && env[method.EnvVar] != "" {
				methods = append(methods, method)
			}
		}
	}
	return methods
}
