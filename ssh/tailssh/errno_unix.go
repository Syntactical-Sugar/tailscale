// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"errors"
	"syscall"
)

// isPtyClosedErr reports whether err is the EIO that Unix returns when
// reading from a PTY master after the child has closed the slave end. The
// SSH run loop uses this to distinguish "process exited" from a real I/O
// error and avoid spurious cancellations.
func isPtyClosedErr(err error) bool {
	return errors.Is(err, syscall.EIO)
}
