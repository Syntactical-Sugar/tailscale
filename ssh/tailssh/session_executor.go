// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"io"
	"os/exec"
)

// sessionExecutor runs the user-side program for a single SSH session.
//
// On Unix-like systems this wraps the incubator subprocess (an exec.Cmd that
// becomes the user's shell after a privilege drop). The Windows
// implementation will instead proxy the session to the local Windows
// OpenSSH server.
//
// Implementations are returned from launchProcess (in OS-specific files) and
// driven by sshSession.run.
type sessionExecutor interface {
	// Stdin returns a writer connected to the user program's standard
	// input.
	Stdin() io.WriteCloser

	// Stdout returns a reader connected to the user program's standard
	// output (or the master end of the PTY for PTY sessions).
	Stdout() io.ReadCloser

	// Stderr returns a reader connected to the user program's standard
	// error, or nil if the session has a PTY (stderr is merged into the
	// PTY stream in that case).
	Stderr() io.ReadCloser

	// ChildPipes returns OS handles owned by the user program (e.g. the
	// slave end of the PTY, or the child halves of stdio pipes) that
	// must be closed by the SSH server after the program exits to
	// release file descriptors and unblock io.Copy goroutines.
	ChildPipes() []io.Closer

	// Wait blocks until the user program exits.
	//
	// If the program exited non-zero, the returned error satisfies
	// interface{ ExitCode() int } so the run loop can extract the exit
	// status to report back over the SSH channel.
	Wait() error

	// Kill terminates the user program. It is invoked when the SSH
	// session's context is canceled (e.g. the client disconnected, or
	// session recording failed).
	Kill() error
}

// cmdExecutor adapts an exec.Cmd to sessionExecutor. It is used by the Unix
// and plan9 incubator paths.
type cmdExecutor struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	childPipes []io.Closer
}

func (e *cmdExecutor) Stdin() io.WriteCloser   { return e.stdin }
func (e *cmdExecutor) Stdout() io.ReadCloser   { return e.stdout }
func (e *cmdExecutor) Stderr() io.ReadCloser   { return e.stderr }
func (e *cmdExecutor) ChildPipes() []io.Closer { return e.childPipes }
func (e *cmdExecutor) Wait() error             { return e.cmd.Wait() }
func (e *cmdExecutor) Kill() error             { return e.cmd.Process.Kill() }
