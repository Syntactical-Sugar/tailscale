# Tailscale SSH on Windows (via OpenSSH delegation)

## Goal

Make Tailscale SSH usable on Windows hosts as a Tailscale SSH *server* (accept
incoming SSH from the tailnet). Today it is hard-blocked: `envknob/featureknob`
returns "The Tailscale SSH server is not supported on windows", and every file
in `ssh/tailssh/` has a build tag that excludes Windows.

A native port would require us to reimplement the Unix incubator on Windows:
ConPTY, `LogonUser`, `CreateProcessAsUser`, token management, profile loading,
Event Log integration. That's a large attack surface to author and maintain.

This plan takes a different route: **delegate process execution to Windows'
built-in OpenSSH server** (an opt-in optional component since Windows 10 1809
and Server 2019), while Tailscale continues to terminate the *outer* SSH
connection from the tailnet and enforce tailnet auth, ACLs, recording, and
check-mode.

## Architecture

```
tailnet client ──SSH──▶ wintun ──▶ tailscaled netstack ──▶ Tailscale SSH server
                                                                  │
                                                       (tailnet auth, ACLs,
                                                        recording, check-mode)
                                                                  │
                                                                  ▼
                                          ssh dial to 127.0.0.1:22 as $TARGET_USER
                                          using a freshly-minted, short-lived
                                          CA-signed certificate
                                                                  │
                                                                  ▼
                                                        Windows OpenSSH (sshd)
                                                                  │
                                                       (ConPTY, LogonUser,
                                                        CreateProcessAsUser,
                                                        shell launch)
```

### Why this works without a port-22 dance

Tailscale SSH terminates inside tailscaled's userspace netstack on the tailnet
IPs. It does not bind a normal OS socket on port 22. So a Windows OpenSSH
listening on `0.0.0.0:22` serving LAN/loopback continues to work unchanged.
Tailnet traffic to `100.x.y.z:22` is intercepted at the wintun layer before the
Windows TCP stack ever sees it.

The *inner* connection is an ordinary outbound TCP dial from tailscaled to
`127.0.0.1:22`, which hits the local OpenSSH service like any other loopback
client.

### Why CA-cert auth, not per-session keys in authorized_keys

Two choices for letting tailscaled authenticate to local sshd as the target
user:

1. **Per-session ephemeral keypair** written to `%USERPROFILE%\.ssh\authorized_keys`
   (or `%ProgramData%\ssh\administrators_authorized_keys` for admins).
   Requires writing into user profiles, cleanup logic, and is messy if we
   crash mid-session.

2. **Tailscale acts as an SSH CA.** Trust the CA's public key once via sshd_config.
   Mint short-lived (≈30 s) user certificates per session, with the target
   Windows username as the cert's `principals`. Self-cleaning via expiry.
   No per-user file writes.

We pick (2).

## Code locations

### Files currently gating Windows

- `envknob/featureknob/featureknob.go:36` — explicit error for `runtime.GOOS == "windows"`. Loosen.
- `feature/ssh/ssh.go:4` — build tag. Add `windows`.
- `cmd/tailscaled/ssh.go:4` — build tag. Add `windows`.
- `ssh/tailssh/tailssh.go:4` — build tag. Add `windows`.
- `ssh/tailssh/user.go:4` — build tag. Add `windows`.
- `ssh/tailssh/hostkeys.go:4` — build tag. Add `windows`.
- `ssh/tailssh/c2n.go:4` — build tag. Add `windows`.

### Files that stay Linux/Unix-only

- `ssh/tailssh/incubator.go` — Unix-only by design; the whole point of this
  plan is that Windows does not use it.
- `ssh/tailssh/incubator_linux.go` — systemd-logind D-Bus.
- `ssh/tailssh/incubator_plan9.go`.
- `ssh/tailssh/auditd_linux.go` — Linux audit netlink.

### New files

- `ssh/tailssh/session_executor.go` — interface that abstracts "run a user's
  session" so the SSH-server side of `tailssh.go` doesn't care whether the
  executor is the Unix incubator or the Windows delegation backend.
- `ssh/tailssh/session_executor_unix.go` — adapter wrapping the existing
  `exec.Cmd`-based incubator path. Build tag: the current non-Windows set.
- `ssh/tailssh/session_executor_windows.go` — the OpenSSH delegation backend.
- `ssh/tailssh/user_windows.go` — Windows user lookup (default shell, home dir).
- `ssh/tailssh/hostkeys_windows.go` — host key storage under
  `%ProgramData%\Tailscale\ssh\` with appropriate ACLs.
- `ssh/tailssh/ca_windows.go` — Tailscale-as-SSH-CA: generate, persist, mint
  short-lived user certs.
- `ssh/tailssh/sshd_config_windows.go` — OpenSSH-server detection, drop-in
  config installer (`%ProgramData%\ssh\sshd_config.d\tailscale.conf`), and
  idempotent injection of the `Include sshd_config.d\*.conf` line into the
  main config if missing.

### Refactor in `ssh/tailssh/tailssh.go`

The current `sshSession` struct (lines 738–770) carries fields specific to the
`exec.Cmd` model (`cmd *exec.Cmd`, `wrStdin`, `rdStdout`, `rdStderr`,
`childPipes`, `ptyReq`). `launchProcess()` (called from line 1034) populates
these. `killProcessOnContextDone` and the run loop consume them.

We will introduce a `sessionExecutor` interface with methods covering what the
run loop actually needs:

- `Start(ctx, ptyReq *gliderssh.Pty, env []string) error`
- `Stdin() io.WriteCloser`
- `Stdout() io.Reader`
- `Stderr() io.Reader` (nil for pty sessions, matching the existing contract)
- `Wait() error` (returns an `*exec.ExitError`-equivalent or our own typed error
  carrying exit code / signal)
- `Resize(rows, cols uint16) error`
- `Signal(sig os.Signal) error`
- `Kill() error`

The Unix path keeps its current `exec.Cmd` machinery, just wrapped behind this
interface. The Windows path satisfies the same interface using a
`golang.org/x/crypto/ssh.Session` against local OpenSSH.

This refactor is the single largest structural change in the plan and should
land in its own commit so it can be reviewed independently of any Windows
logic.

## Subsystems

OpenSSH's subsystem support (sftp, scp via sftp, port forwarding) flows
through the same session abstraction. By proxying the channel as-is — not
just stdin/stdout but `exec` / `subsystem` / `shell` requests — we get sftp
and friends for free.

The existing `accept_env.go` env-var filtering still applies to the *outer*
request before we issue the inner request, so the env-filter policy is
unchanged.

## CA management

`ca_windows.go`:

- On first SSH enable, generate an Ed25519 CA keypair.
- Persist private key at `%ProgramData%\Tailscale\ssh\ca`, mode = ACL granting
  only SYSTEM + Administrators full control (no inherited ACEs). Public key
  alongside as `ca.pub`.
- A `MintUserCert(username string, validity time.Duration) (signed []byte, signer ssh.Signer, err error)`
  function produces a fresh user keypair and signs a certificate with:
  - `CertType = ssh.UserCert`
  - `KeyId = "tailscale-ssh-<sharedID>"`
  - `ValidPrincipals = [username]`
  - `ValidAfter = now - 5s`, `ValidBefore = now + 30s`
  - Standard permissions (no source-address restrictions; loopback only).

Short validity windows are safe because the cert is consumed immediately by
our own local dial. The signer's private key never leaves the process.

## sshd_config drop-in

`sshd_config_windows.go`:

- Detect `%ProgramData%\ssh\sshd_config` existence. If absent: report
  "OpenSSH Server not installed" with a hint to run
  `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.
- Detect whether the file has an `Include sshd_config.d\*.conf` directive.
  If not, append one inside a delimited managed block:
  ```
  # BEGIN TAILSCALE MANAGED BLOCK
  Include sshd_config.d\*.conf
  # END TAILSCALE MANAGED BLOCK
  ```
  Idempotent on re-run.
- Write our drop-in to `%ProgramData%\ssh\sshd_config.d\tailscale.conf`:
  ```
  # Managed by Tailscale — do not edit.
  TrustedUserCAKeys __PROGRAMDATA__/Tailscale/ssh/ca.pub
  ```
- Restart `sshd` service (`Get-Service sshd`, `Restart-Service sshd` via the
  Service Control Manager API; not by shelling out to PowerShell).
- All file ops use ACLs that grant SYSTEM + Administrators only.

This runs lazily the first time Tailscale SSH is enabled on a Windows host,
not at install time. Disabling Tailscale SSH should remove the drop-in (but
leave the `Include` line; it's harmless if the directory is empty).

## Feature gate

`envknob/featureknob/featureknob.go:CanRunTailscaleSSH`:

- Allow `runtime.GOOS == "windows"` *only* if OpenSSH server is available.
- A new helper `windowsOpenSSHAvailable()` checks for the existence of
  `%ProgramData%\ssh\sshd_config`. (Service running status is checked at
  enable-time, not here — a stopped service should give a clearer error than
  a generic "not supported".)

## Open questions / risks

1. **OpenSSH version skew.** Cert auth on Windows OpenSSH has had bugs in older
   builds. Server 2019's ships ≈7.x. We may need a minimum version check.
   Decision: Park as a follow-up; surface the version in error output if cert
   auth fails so users can self-diagnose.

2. **`__PROGRAMDATA__` token in TrustedUserCAKeys.** OpenSSH-for-Windows
   supports this token (it expands to `C:\ProgramData`). Worth confirming on
   the test VM before committing to it; if not, hardcode the resolved path.

3. **Username canonicalization.** Tailnet ACLs grant access as `alice`; sshd
   on Windows may want `MACHINE\alice`. Our cert's `ValidPrincipals` and the
   `User` field of the inner ssh.ClientConfig must match what OpenSSH expects.
   Test with local-only accounts first; AD/domain-joined behaviour parked as
   a follow-up.

4. **Default shell.** Windows OpenSSH's default shell is `cmd.exe` unless the
   registry value `HKLM:\SOFTWARE\OpenSSH\DefaultShell` is set. We do not
   touch this — users keep whatever they configured.

5. **Disabling sshd while Tailscale SSH is enabled.** If the sshd service is
   stopped after enable, our inner dial fails. Surface a clean error to the
   tailnet client rather than a generic dial error.

6. **Session recording / check-mode.** Both happen at the outer connection
   layer, *before* the inner dial. Should continue to work without changes
   since the executor refactor preserves the channel-level hooks. Verify in
   manual testing.

## Out of scope (for now)

- Native ConPTY-based implementation (no OpenSSH dependency). Could be
  revisited if there's demand for features the delegation approach can't
  support.
- Auto-install of OpenSSH server via DISM. We detect and instruct; we do not
  install. Reduces surprise and avoids elevation prompts.
- Domain accounts. Local accounts first.
- Sandboxed/Store builds of Tailscale. Out of scope; the gate already excludes
  these.

## Implementation sequence

Each item is its own commit (or small stack of commits).

1. `plan:` — this document.
2. Refactor: extract the Unix session-runner behind a `sessionExecutor`
   interface, no behaviour change. Make sure all existing tests still pass.
3. Add `user_windows.go` (lookup, default shell).
4. Add `hostkeys_windows.go` (`%ProgramData%\Tailscale\ssh\`).
5. Add `ca_windows.go` (generation, persistence, MintUserCert).
6. Add `sshd_config_windows.go` (detection, drop-in installer, idempotency).
7. Add `session_executor_windows.go` (the delegation backend).
8. Loosen build tags on `tailssh.go`, `user.go`, `hostkeys.go`, `c2n.go`,
   `feature/ssh/ssh.go`, `cmd/tailscaled/ssh.go` to include Windows.
9. Loosen the `featureknob.CanRunTailscaleSSH` gate.
10. `unplan:` — delete this plan file once everything is shipped.

Manual Windows VM testing happens between (7) and the final tag-loosening
commits, so we don't expose a half-working feature.

## Testing notes

Most testing of the new code is unit-level (CA mint round-trip, drop-in idempotency,
sshd_config parsing). The interesting end-to-end is manual on a Windows VM —
see the separate requirements list captured in the conversation, but in short:

- Server 2022 or Win11, OpenSSH Server installed and started.
- A non-admin local user in addition to an admin.
- Cross-compile `tailscaled.exe` + `tailscale.exe` from Linux, deploy via tailnet.
- Verify: shell, exit codes, window resize, sftp, environment variables, that
  enabling/disabling Tailscale SSH doesn't break a non-Tailscale OpenSSH client
  connecting on the LAN.
