// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package tailssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/crypto/ssh"
)

// launchProcess on Windows opens an inner SSH session to the local
// Windows OpenSSH server as the target user, authenticated with a
// short-lived certificate minted by our delegation CA. The inner session
// is then proxied to the outer (tailnet) session by the SSH server's run
// loop via the sessionExecutor interface.
func (ss *sshSession) launchProcess() error {
	ca, err := ensureDelegationCA(ss.conn.srv)
	if err != nil {
		return fmt.Errorf("delegation setup: %w", err)
	}

	principal := windowsCertPrincipal(ss.conn.localUser.Username)
	signer, err := ca.MintUserCert(principal, 30*time.Second)
	if err != nil {
		return fmt.Errorf("mint cert: %w", err)
	}

	client, err := dialLocalSSHD(principal, signer)
	if err != nil {
		return fmt.Errorf("dial local sshd: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return fmt.Errorf("new inner session: %w", err)
	}

	for _, kv := range ss.Environ() {
		if !acceptEnvPair(kv) {
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// Setenv errors are best-effort — OpenSSH may reject env vars
		// not in its AcceptEnv list. We've already filtered at our
		// own policy layer.
		_ = session.Setenv(key, val)
	}

	ptyReq, winCh, isPty := ss.Pty()
	if isPty {
		modes := ssh.TerminalModes{}
		for k, v := range ptyReq.Modes {
			modes[k] = v
		}
		if err := session.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, modes); err != nil {
			session.Close()
			client.Close()
			return fmt.Errorf("inner RequestPty: %w", err)
		}
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return fmt.Errorf("inner StdinPipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return fmt.Errorf("inner StdoutPipe: %w", err)
	}
	var stderr io.Reader
	if !isPty {
		stderr, err = session.StderrPipe()
		if err != nil {
			session.Close()
			client.Close()
			return fmt.Errorf("inner StderrPipe: %w", err)
		}
	}

	if err := startInnerSession(session, ss); err != nil {
		session.Close()
		client.Close()
		return err
	}

	if isPty {
		go forwardWindowChanges(session, winCh, ss.logf)
	}

	exec := &winDelegationExecutor{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  noopReadCloser{stdout},
	}
	if stderr != nil {
		exec.stderr = noopReadCloser{stderr}
	}
	ss.executor = exec
	return nil
}

// startInnerSession dispatches between subsystem (sftp), explicit command,
// and interactive shell on the inner SSH session, mirroring what the
// outer client requested.
func startInnerSession(session *ssh.Session, ss *sshSession) error {
	if sub := ss.Subsystem(); sub != "" {
		if err := session.RequestSubsystem(sub); err != nil {
			return fmt.Errorf("inner RequestSubsystem(%q): %w", sub, err)
		}
		return nil
	}
	if cmd := ss.RawCommand(); cmd != "" {
		if err := session.Start(cmd); err != nil {
			return fmt.Errorf("inner Start: %w", err)
		}
		return nil
	}
	if err := session.Shell(); err != nil {
		return fmt.Errorf("inner Shell: %w", err)
	}
	return nil
}

// dialLocalSSHD opens an SSH client to the local Windows OpenSSH server on
// 127.0.0.1:22 as user, authenticating with the supplied cert+key signer.
//
// The host key callback is permissive: the connection target is the
// loopback adapter on the same machine, so MITM is not a meaningful
// threat. The traffic never leaves the host.
func dialLocalSSHD(user string, signer ssh.Signer) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "127.0.0.1:22", cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// forwardWindowChanges forwards window-size changes from the outer client
// to the inner sshd session for the duration of the session.
func forwardWindowChanges(session *ssh.Session, winCh <-chan gliderssh.Window, logf func(string, ...any)) {
	for win := range winCh {
		if err := session.WindowChange(win.Height, win.Width); err != nil {
			logf("tailssh: inner WindowChange: %v", err)
			return
		}
	}
}

// windowsCertPrincipal returns the certificate principal to request for a
// gliderssh username. Tailnet ACLs and our userLookup deal in bare local
// usernames (e.g. "alice"); the Windows OpenSSH cert principal must match
// what sshd expects, which is also the bare local username. Strip a
// leading "DOMAIN\" or "MACHINE\" prefix if one has slipped in.
func windowsCertPrincipal(username string) string {
	if i := strings.LastIndex(username, `\`); i >= 0 {
		return username[i+1:]
	}
	return username
}

// noopReadCloser wraps an io.Reader as io.ReadCloser with a no-op Close.
// The sessionExecutor interface returns io.ReadCloser, but x/crypto/ssh
// session pipes are io.Reader only — closing the local end has no remote
// effect, and the run loop's deferred Close() is purely tidy-up.
type noopReadCloser struct{ io.Reader }

func (noopReadCloser) Close() error { return nil }

// winDelegationExecutor adapts an inner ssh.Client+Session to the
// sessionExecutor interface.
type winDelegationExecutor struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser // nil for PTY sessions

	killOnce sync.Once
}

func (e *winDelegationExecutor) Stdin() io.WriteCloser   { return e.stdin }
func (e *winDelegationExecutor) Stdout() io.ReadCloser   { return e.stdout }
func (e *winDelegationExecutor) Stderr() io.ReadCloser   { return e.stderr }
func (e *winDelegationExecutor) ChildPipes() []io.Closer { return nil }

func (e *winDelegationExecutor) Wait() error {
	err := e.session.Wait()
	// Tear down the underlying connection unconditionally — the run loop
	// is the sole owner of this executor and won't reuse it.
	e.client.Close()
	if err == nil {
		return nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return &innerExitError{code: exitErr.ExitStatus(), inner: err}
	}
	return err
}

func (e *winDelegationExecutor) Kill() error {
	e.killOnce.Do(func() {
		e.session.Close()
		e.client.Close()
	})
	return nil
}

// innerExitError wraps an *ssh.ExitError to satisfy the run loop's
// interface{ ExitCode() int } shape (which *exec.ExitError implements via
// its embedded *os.ProcessState).
type innerExitError struct {
	code  int
	inner error
}

func (e *innerExitError) Error() string { return e.inner.Error() }
func (e *innerExitError) ExitCode() int { return e.code }
func (e *innerExitError) Unwrap() error { return e.inner }

// ensureDelegationCA returns the per-process delegation CA, lazily
// initialising it (and writing the sshd_config drop-in) on first use.
//
// On failure the result is not cached so a subsequent SSH attempt can
// retry — useful when the user fixes a precondition (e.g. installing
// OpenSSH Server) without restarting tailscaled.
var (
	delegationCAMu  sync.Mutex
	delegationCAVal *delegationCA
)

func ensureDelegationCA(srv *server) (*delegationCA, error) {
	delegationCAMu.Lock()
	defer delegationCAMu.Unlock()
	if delegationCAVal != nil {
		return delegationCAVal, nil
	}
	varRoot := srv.lb.TailscaleVarRoot()
	if varRoot == "" {
		return nil, errors.New("no Tailscale var root; cannot persist SSH delegation CA")
	}
	ca, err := setUpDelegation(varRoot, srv.logf)
	if err != nil {
		return nil, err
	}
	delegationCAVal = ca
	return ca, nil
}
