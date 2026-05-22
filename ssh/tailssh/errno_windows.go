// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package tailssh

// isPtyClosedErr always reports false on Windows. The Tailscale SSH
// server on Windows does not own a local PTY (sessions are proxied to
// local OpenSSH, which runs ConPTY on the user's behalf), so the
// Unix-only "EIO after child closes slave" condition has no analogue here.
func isPtyClosedErr(err error) bool {
	return false
}
