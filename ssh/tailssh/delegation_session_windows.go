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
	ss.logf("tailssh-win: launchProcess: begin (user=%q raw=%q cmd=%q subsystem=%q)",
		ss.conn.localUser.Username, ss.User(), ss.RawCommand(), ss.Subsystem())

	ca, err := ensureDelegationCA(ss.conn.srv)
	if err != nil {
		ss.logf("tailssh-win: launchProcess: ensureDelegationCA failed: %v", err)
		return fmt.Errorf("delegation setup: %w", err)
	}
	ss.logf("tailssh-win: launchProcess: CA ready")

	principal := windowsCertPrincipal(ss.conn.localUser.Username)
	ss.logf("tailssh-win: launchProcess: principal=%q (from username=%q)", principal, ss.conn.localUser.Username)
	signer, err := ca.MintUserCert(principal, 30*time.Second)
	if err != nil {
		ss.logf("tailssh-win: launchProcess: MintUserCert failed: %v", err)
		return fmt.Errorf("mint cert: %w", err)
	}
	ss.logf("tailssh-win: launchProcess: cert minted for principal=%q", principal)

	client, err := dialLocalSSHD(principal, signer, ss.logf)
	if err != nil {
		ss.logf("tailssh-win: launchProcess: dialLocalSSHD failed: %v", err)
		return fmt.Errorf("dial local sshd: %w", err)
	}
	ss.logf("tailssh-win: launchProcess: dialed sshd; opening inner session")

	session, err := client.NewSession()
	if err != nil {
		ss.logf("tailssh-win: launchProcess: NewSession failed: %v", err)
		client.Close()
		return fmt.Errorf("new inner session: %w", err)
	}
	ss.logf("tailssh-win: launchProcess: inner session opened")

	for _, kv := range ss.Environ() {
		if !acceptEnvPair(kv) {
			ss.logf("tailssh-win: launchProcess: skip env (filtered): %q", kv)
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			ss.logf("tailssh-win: launchProcess: skip env (no =): %q", kv)
			continue
		}
		// Setenv errors are best-effort — OpenSSH may reject env vars
		// not in its AcceptEnv list. We've already filtered at our
		// own policy layer.
		if err := session.Setenv(key, val); err != nil {
			ss.logf("tailssh-win: launchProcess: inner Setenv(%q) declined: %v", key, err)
		} else {
			ss.logf("tailssh-win: launchProcess: inner Setenv(%q)=%q ok", key, val)
		}
	}

	ptyReq, winCh, isPty := ss.Pty()
	ss.logf("tailssh-win: launchProcess: pty=%v term=%q size=%dx%d", isPty, ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width)
	if isPty {
		modes := ssh.TerminalModes{}
		for k, v := range ptyReq.Modes {
			modes[k] = v
		}
		if err := session.RequestPty(ptyReq.Term, ptyReq.Window.Height, ptyReq.Window.Width, modes); err != nil {
			ss.logf("tailssh-win: launchProcess: inner RequestPty failed: %v", err)
			session.Close()
			client.Close()
			return fmt.Errorf("inner RequestPty: %w", err)
		}
		ss.logf("tailssh-win: launchProcess: inner RequestPty ok")
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		ss.logf("tailssh-win: launchProcess: inner StdinPipe failed: %v", err)
		session.Close()
		client.Close()
		return fmt.Errorf("inner StdinPipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		ss.logf("tailssh-win: launchProcess: inner StdoutPipe failed: %v", err)
		session.Close()
		client.Close()
		return fmt.Errorf("inner StdoutPipe: %w", err)
	}
	var stderr io.Reader
	if !isPty {
		stderr, err = session.StderrPipe()
		if err != nil {
			ss.logf("tailssh-win: launchProcess: inner StderrPipe failed: %v", err)
			session.Close()
			client.Close()
			return fmt.Errorf("inner StderrPipe: %w", err)
		}
		ss.logf("tailssh-win: launchProcess: inner StderrPipe ok")
	}

	if err := startInnerSession(session, ss); err != nil {
		ss.logf("tailssh-win: launchProcess: startInnerSession failed: %v", err)
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
		logf:    ss.logf,
	}
	if stderr != nil {
		exec.stderr = noopReadCloser{stderr}
	}
	ss.executor = exec
	ss.logf("tailssh-win: launchProcess: session running")
	return nil
}

// startInnerSession dispatches between subsystem (sftp), explicit command,
// and interactive shell on the inner SSH session, mirroring what the
// outer client requested.
func startInnerSession(session *ssh.Session, ss *sshSession) error {
	if sub := ss.Subsystem(); sub != "" {
		ss.logf("tailssh-win: startInnerSession: RequestSubsystem(%q)", sub)
		if err := session.RequestSubsystem(sub); err != nil {
			return fmt.Errorf("inner RequestSubsystem(%q): %w", sub, err)
		}
		ss.logf("tailssh-win: startInnerSession: subsystem started")
		return nil
	}
	if cmd := ss.RawCommand(); cmd != "" {
		ss.logf("tailssh-win: startInnerSession: Start(%q)", cmd)
		if err := session.Start(cmd); err != nil {
			return fmt.Errorf("inner Start: %w", err)
		}
		ss.logf("tailssh-win: startInnerSession: command started")
		return nil
	}
	ss.logf("tailssh-win: startInnerSession: Shell()")
	if err := session.Shell(); err != nil {
		return fmt.Errorf("inner Shell: %w", err)
	}
	ss.logf("tailssh-win: startInnerSession: shell started")
	return nil
}

// dialLocalSSHD opens an SSH client to the local Windows OpenSSH server on
// 127.0.0.1:22 as user, authenticating with the supplied cert+key signer.
//
// The host key callback is permissive: the connection target is the
// loopback adapter on the same machine, so MITM is not a meaningful
// threat. The traffic never leaves the host.
func dialLocalSSHD(user string, signer ssh.Signer, logf func(string, ...any)) (*ssh.Client, error) {
	const addr = "127.0.0.1:22"
	logf("tailssh-win: dialLocalSSHD: dialing %s as user=%q", addr, user)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logf("tailssh-win: dialLocalSSHD: TCP dial failed: %v", err)
		return nil, err
	}
	logf("tailssh-win: dialLocalSSHD: TCP connected; starting SSH handshake")
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		logf("tailssh-win: dialLocalSSHD: SSH handshake failed: %v", err)
		conn.Close()
		return nil, err
	}
	logf("tailssh-win: dialLocalSSHD: SSH handshake ok")
	return ssh.NewClient(c, chans, reqs), nil
}

// forwardWindowChanges forwards window-size changes from the outer client
// to the inner sshd session for the duration of the session.
func forwardWindowChanges(session *ssh.Session, winCh <-chan gliderssh.Window, logf func(string, ...any)) {
	logf("tailssh-win: forwardWindowChanges: started")
	for win := range winCh {
		logf("tailssh-win: forwardWindowChanges: %dx%d", win.Height, win.Width)
		if err := session.WindowChange(win.Height, win.Width); err != nil {
			logf("tailssh-win: forwardWindowChanges: WindowChange failed: %v", err)
			return
		}
	}
	logf("tailssh-win: forwardWindowChanges: ended (channel closed)")
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
	logf    func(string, ...any)

	killOnce sync.Once
}

func (e *winDelegationExecutor) Stdin() io.WriteCloser   { return e.stdin }
func (e *winDelegationExecutor) Stdout() io.ReadCloser   { return e.stdout }
func (e *winDelegationExecutor) Stderr() io.ReadCloser   { return e.stderr }
func (e *winDelegationExecutor) ChildPipes() []io.Closer { return nil }

func (e *winDelegationExecutor) Wait() error {
	e.logf("tailssh-win: executor.Wait: waiting for inner session")
	err := e.session.Wait()
	// Tear down the underlying connection unconditionally — the run loop
	// is the sole owner of this executor and won't reuse it.
	e.client.Close()
	if err == nil {
		e.logf("tailssh-win: executor.Wait: inner session exited 0")
		return nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		e.logf("tailssh-win: executor.Wait: inner exit code=%d signal=%q msg=%q", exitErr.ExitStatus(), exitErr.Signal(), exitErr.Msg())
		return &innerExitError{code: exitErr.ExitStatus(), inner: err}
	}
	e.logf("tailssh-win: executor.Wait: inner err: %v", err)
	return err
}

func (e *winDelegationExecutor) Kill() error {
	e.killOnce.Do(func() {
		e.logf("tailssh-win: executor.Kill: closing inner session and client")
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
		srv.logf("tailssh-win: ensureDelegationCA: using cached CA")
		return delegationCAVal, nil
	}
	srv.logf("tailssh-win: ensureDelegationCA: no cached CA; running setUpDelegation")
	varRoot := srv.lb.TailscaleVarRoot()
	if varRoot == "" {
		srv.logf("tailssh-win: ensureDelegationCA: no var root")
		return nil, errors.New("no Tailscale var root; cannot persist SSH delegation CA")
	}
	srv.logf("tailssh-win: ensureDelegationCA: varRoot=%q", varRoot)
	ca, err := setUpDelegation(varRoot, srv.logf)
	if err != nil {
		srv.logf("tailssh-win: ensureDelegationCA: setUpDelegation failed: %v", err)
		return nil, err
	}
	srv.logf("tailssh-win: ensureDelegationCA: setUpDelegation ok; caching CA")
	delegationCAVal = ca
	return ca, nil
}
