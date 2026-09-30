package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kandev/kandev/internal/agent/agents"
	agentctl "github.com/kandev/kandev/internal/agent/runtime/agentctl"
	agentctltypes "github.com/kandev/kandev/internal/agentctl/types"
)

// shellProcessClient runs agentctl process requests with the local shell and, like
// agentctl, forgets a process as soon as it exits.
type shellProcessClient struct {
	mu        sync.Mutex
	commands  []string
	processes map[string]*shellProcess
}

type shellProcess struct {
	cmd    *exec.Cmd
	output *lockedBuffer
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (c *shellProcessClient) StartProcess(_ context.Context, req agentctl.StartProcessRequest) (*agentctl.ProcessInfo, error) {
	cmd := exec.Command("sh", "-c", req.Command)
	cmd.Env = os.Environ()
	for key, value := range req.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands = append(c.commands, req.Command)
	if c.processes == nil {
		c.processes = map[string]*shellProcess{}
	}
	id := fmt.Sprintf("process-%d", len(c.commands))
	c.processes[id] = &shellProcess{cmd: cmd, output: output}
	go func() {
		_ = cmd.Wait()
		c.mu.Lock()
		delete(c.processes, id)
		c.mu.Unlock()
	}()
	return &agentctl.ProcessInfo{ID: id, Status: agentctltypes.ProcessStatusRunning}, nil
}

func (c *shellProcessClient) GetProcess(_ context.Context, id string, _ bool) (*agentctl.ProcessInfo, error) {
	c.mu.Lock()
	process, ok := c.processes[id]
	c.mu.Unlock()
	if !ok {
		return nil, errors.New("get process failed with status 404")
	}
	return &agentctl.ProcessInfo{
		ID: id, Status: agentctltypes.ProcessStatusRunning,
		Output: []agentctl.ProcessOutputChunk{{Data: process.output.String()}},
	}, nil
}

func (c *shellProcessClient) StopProcess(_ context.Context, id string) error {
	c.mu.Lock()
	process, ok := c.processes[id]
	c.mu.Unlock()
	if ok {
		_ = process.cmd.Process.Kill()
	}
	return nil
}

func TestAgentctlFileUploaderRoundTrip(t *testing.T) {
	client := &shellProcessClient{}
	t.Cleanup(func() { stopAll(client) })
	uploader := agentctlFileUploader{client: client, sessionID: "session-1"}
	path := filepath.Join(t.TempDir(), "nested", "auth.json")
	secret := []byte("{\"token\":\"s3cr3t\"}\n")

	if _, err := uploader.ReadFile(context.Background(), path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile of a missing file = %v, want fs.ErrNotExist", err)
	}
	if err := uploader.WriteFile(context.Background(), path, secret, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("written file = %v, %v; want mode 0600", info, err)
	}
	got, err := uploader.ReadFile(context.Background(), path)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	for _, command := range client.commands {
		if strings.Contains(command, "s3cr3t") || strings.Contains(command, path) {
			t.Fatalf("command line carries file data or path: %s", command)
		}
	}
}

func TestUploadPluginExecutorAgentCredentialsCopiesSelectedFiles(t *testing.T) {
	localHome := t.TempDir()
	t.Setenv("HOME", localHome)
	source := filepath.Join(localHome, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(`{"opencode":{"type":"api","key":"k"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteHome := t.TempDir()
	existing := filepath.Join(remoteHome, ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(existing), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte(`{"other":{"type":"api","key":"x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	executor := NewPluginRemoteExecutor(nil, newTestLogger())
	req := &ExecutorCreateRequest{
		SessionID:   "session-1",
		AgentConfig: agents.NewOpenCodeACP(),
		Metadata: map[string]interface{}{
			"remote_credentials":      `["agent:opencode-acp:files:0"]`,
			MetadataKeyRemoteAuthHome: remoteHome,
		},
	}
	executor.uploadPluginExecutorAgentCredentials(context.Background(), &shellProcessClient{}, req)

	merged, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("read uploaded credentials: %v", err)
	}
	if !strings.Contains(string(merged), `"opencode"`) || !strings.Contains(string(merged), `"other"`) {
		t.Fatalf("uploaded auth.json = %s, want the local entry merged into the existing file", merged)
	}
}

func TestUploadPluginExecutorAgentCredentialsWithoutSelectionRunsNothing(t *testing.T) {
	client := &shellProcessClient{}
	executor := NewPluginRemoteExecutor(nil, newTestLogger())
	executor.uploadPluginExecutorAgentCredentials(context.Background(), client, &ExecutorCreateRequest{
		SessionID: "session-1", AgentConfig: agents.NewOpenCodeACP(), Metadata: map[string]interface{}{},
	})
	if len(client.commands) != 0 {
		t.Fatalf("commands = %v, want none", client.commands)
	}
}

func stopAll(client *shellProcessClient) {
	client.mu.Lock()
	defer client.mu.Unlock()
	for _, process := range client.processes {
		_ = process.cmd.Process.Kill()
	}
}
