package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInstanceLeaseIsExclusivePerStateFile(t *testing.T) {
	r := require.New(t)
	statePath := filepath.Join(t.TempDir(), "state.db")

	first, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.True(acquired)

	second, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.False(acquired)
	r.NoError(second.Close())
	r.NoError(first.Close())

	third, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.True(acquired)
	r.NoError(third.Close())
}

func TestInstanceLeasesAllowDifferentStateFiles(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()

	first, acquired, err := acquireInstanceLease(filepath.Join(dir, "first.db"))
	r.NoError(err)
	r.True(acquired)
	t.Cleanup(func() { r.NoError(first.Close()) })

	second, acquired, err := acquireInstanceLease(filepath.Join(dir, "second.db"))
	r.NoError(err)
	r.True(acquired)
	t.Cleanup(func() { r.NoError(second.Close()) })
}

func TestWaitForRunningInstance(t *testing.T) {
	r := require.New(t)
	app := &webApp{instanceToken: "study-group-token"}
	server := httptest.NewServer(app.adminRoutes())
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "state.db")
	owner, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.True(acquired)
	t.Cleanup(func() { r.NoError(owner.Close()) })
	want := instanceMetadata{URL: server.URL, Token: app.instanceToken}
	r.NoError(owner.Publish(want))
	waiter, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.False(acquired)
	t.Cleanup(func() { r.NoError(waiter.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	got, acquired, err := waitForRunningInstance(ctx, waiter)
	r.NoError(err)
	r.False(acquired)
	r.Equal(want, got)
}

func TestWaitForRunningInstanceTakesOverReleasedLease(t *testing.T) {
	r := require.New(t)
	statePath := filepath.Join(t.TempDir(), "state.db")
	owner, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.True(acquired)
	waiter, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.False(acquired)
	t.Cleanup(func() { r.NoError(waiter.Close()) })

	r.NoError(owner.Close())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	_, acquired, err = waitForRunningInstance(ctx, waiter)
	r.NoError(err)
	r.True(acquired)
}

func TestInstanceLeaseCanonicalizesStateSymlink(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	r.NoError(os.WriteFile(statePath, nil, 0o600))
	aliasPath := filepath.Join(dir, "state-alias.db")
	r.NoError(os.Symlink(statePath, aliasPath))

	owner, acquired, err := acquireInstanceLease(statePath)
	r.NoError(err)
	r.True(acquired)
	t.Cleanup(func() { r.NoError(owner.Close()) })
	waiter, acquired, err := acquireInstanceLease(aliasPath)
	r.NoError(err)
	r.False(acquired)
	r.NoError(waiter.Close())
}

func TestInstanceLeaseRejectsLockSymlink(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	lockPath, err := instanceLockPath(statePath)
	r.NoError(err)
	targetPath := filepath.Join(dir, "important.txt")
	r.NoError(os.WriteFile(targetPath, []byte("Greendale"), 0o600))
	r.NoError(os.Symlink(targetPath, lockPath))

	_, _, err = acquireInstanceLease(statePath)
	r.Error(err)
	contents, err := os.ReadFile(targetPath)
	r.NoError(err)
	r.Equal("Greendale", string(contents))
}

func TestInstanceLeaseRejectsHardLinkedStateFile(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	r.NoError(os.WriteFile(statePath, nil, 0o600))
	r.NoError(os.Link(statePath, filepath.Join(dir, "state-alias.db")))

	_, _, err := acquireInstanceLease(statePath)
	r.ErrorContains(err, "multiple hard links")
}

func TestInstanceLeaseRejectsDanglingStateSymlink(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	r.NoError(os.Symlink(filepath.Join(dir, "missing.db"), statePath))

	_, _, err := acquireInstanceLease(statePath)
	r.ErrorContains(err, "resolve state file")
}

func TestInstanceReadinessRejectsWrongToken(t *testing.T) {
	r := require.New(t)
	app := &webApp{instanceToken: "correct-token"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, instanceReadyPath, nil)
	request.Header.Set(instanceTokenHeader, "wrong-token")

	app.adminRoutes().ServeHTTP(recorder, request)

	r.Equal(http.StatusNotFound, recorder.Code)
}

func TestRepeatedLaunchUsesRunningProcess(t *testing.T) {
	r := require.New(t)
	statePath := filepath.Join(t.TempDir(), "state.db")
	command := instanceHelperCommand(statePath)
	var firstOutput bytes.Buffer
	command.Stdout = &firstOutput
	command.Stderr = &firstOutput
	r.NoError(command.Start())
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("kill helper process: %v", err)
		}
		if err := command.Wait(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Errorf("wait for helper process: %v", err)
			}
		}
	})

	waitForHelperInstance(t, statePath, &firstOutput)
	secondOutput, err := instanceHelperCommand(statePath).CombinedOutput()
	r.NoError(err, string(secondOutput))
	r.Contains(string(secondOutput), "scimtest is already running at http://127.0.0.1:")

	r.NoError(command.Process.Kill())
	err = command.Wait()
	var exitErr *exec.ExitError
	r.ErrorAs(err, &exitErr)
	stopped = true
}

func TestInstanceProcessHelper(t *testing.T) {
	if os.Getenv("SCIMTEST_INSTANCE_HELPER") != "1" {
		return
	}
	require.NoError(t, Run(RunOptions{NoOpen: true}))
}

func instanceHelperCommand(statePath string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestInstanceProcessHelper$")
	command.Env = append(os.Environ(),
		"PORT=",
		"SCIMTEST_INSTANCE_HELPER=1",
		"SCIMTEST_STATE_FILE="+statePath,
	)
	return command
}

func waitForHelperInstance(t *testing.T, statePath string, output *bytes.Buffer) {
	t.Helper()
	r := require.New(t)
	lockPath, err := instanceLockPath(statePath)
	r.NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	for {
		file, openErr := os.Open(lockPath)
		if openErr == nil {
			metadata, metadataErr := readInstanceMetadata(file)
			closeErr := file.Close()
			if closeErr != nil {
				t.Fatalf("close helper instance metadata: %v", closeErr)
			}
			if metadataErr == nil && checkRunningInstance(ctx, metadata) == nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("helper instance did not become ready: %v\n%s", ctx.Err(), output.String())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
