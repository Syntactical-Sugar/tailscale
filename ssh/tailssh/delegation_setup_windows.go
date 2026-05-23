// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package tailssh

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"tailscale.com/types/logger"
)

// Filesystem layout for the Windows delegation backend.
//
// Tailscaled-owned (under varRoot, restrictive ACLs inherited from
// %ProgramData%\Tailscale\):
//   <varRoot>\ssh\delegation_ca_key   — CA private key (OpenSSH PEM format)
//
// OpenSSH-shared (under %ProgramData%\ssh\, ACLs let sshd read):
//   tailscale_ca.pub                  — CA public key (authorized_keys format)
//   sshd_config.d\tailscale.conf      — drop-in config (TrustedUserCAKeys ...)
const (
	caPrivateFileName    = "delegation_ca_key"
	caPublicFileBaseName = "tailscale_ca.pub"
	dropInFileName       = "tailscale.conf"

	tailscaleBeginMarker = "# BEGIN TAILSCALE MANAGED BLOCK"
	tailscaleEndMarker   = "# END TAILSCALE MANAGED BLOCK"
)

// errOpenSSHNotInstalled is returned by setUpDelegation when the Windows
// OpenSSH Server feature is not installed.
var errOpenSSHNotInstalled = errors.New(
	"Windows OpenSSH Server is not installed (run: " +
		`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0)`)

// errOpenSSHNotInitialized is returned when the sshd service is registered
// but has not yet been started and so has not materialized
// %ProgramData%\ssh\sshd_config. We attempt to start it ourselves; this
// error escapes if that doesn't recover.
var errOpenSSHNotInitialized = errors.New(
	"Windows OpenSSH Server is installed but its config directory has " +
		"not been initialized; tried to start the sshd service")

// programDataSSHDir returns the directory that holds the Windows OpenSSH
// server configuration (typically C:\ProgramData\ssh).
func programDataSSHDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "ssh")
	}
	return `C:\ProgramData\ssh`
}

// setUpDelegation prepares the local Windows OpenSSH server to accept
// inner SSH connections from this tailscaled. It is idempotent and safe
// to call on every tailscaled startup.
//
// On success the returned delegationCA can be used to mint short-lived
// per-session user certificates.
func setUpDelegation(varRoot string, logf logger.Logf) (*delegationCA, error) {
	if varRoot == "" {
		return nil, errors.New("tailssh: empty varRoot")
	}

	// OpenSSH installation registers the sshd service in the SCM. That's
	// a stronger signal than the existence of %ProgramData%\ssh\sshd_config,
	// which only appears after sshd has run at least once.
	if err := requireSSHDService(); err != nil {
		return nil, err
	}

	sshDir := programDataSSHDir()
	mainConfig := filepath.Join(sshDir, "sshd_config")
	if _, err := os.Stat(mainConfig); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat %s: %w", mainConfig, err)
		}
		// First-run initialization: start sshd so it creates the
		// directory and copies sshd_config_default into place.
		logf("tailssh: %s missing; starting sshd to initialize it", mainConfig)
		if err := startSSHD(logf); err != nil {
			return nil, fmt.Errorf("initial sshd start: %w", err)
		}
		if _, err := os.Stat(mainConfig); err != nil {
			return nil, errOpenSSHNotInitialized
		}
	}

	ca, err := loadOrCreateCA(varRoot, logf)
	if err != nil {
		return nil, fmt.Errorf("CA setup: %w", err)
	}

	caPubPath := filepath.Join(sshDir, caPublicFileBaseName)
	if err := writeIfChanged(caPubPath, ca.PublicKey(), 0644); err != nil {
		return nil, fmt.Errorf("write CA public key: %w", err)
	}

	dropInDir := filepath.Join(sshDir, "sshd_config.d")
	if err := os.MkdirAll(dropInDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dropInDir, err)
	}
	dropInPath := filepath.Join(dropInDir, dropInFileName)
	dropInBody := dropInConfig(caPubPath)
	dropInChanged, err := writeIfChangedReport(dropInPath, dropInBody, 0644)
	if err != nil {
		return nil, fmt.Errorf("write drop-in: %w", err)
	}

	includeChanged, err := ensureIncludeDirective(mainConfig)
	if err != nil {
		return nil, fmt.Errorf("ensure Include: %w", err)
	}

	if dropInChanged || includeChanged {
		logf("tailssh: sshd config changed (drop-in=%v include=%v); restarting sshd", dropInChanged, includeChanged)
		if err := restartSSHD(logf); err != nil {
			return nil, fmt.Errorf("restart sshd: %w", err)
		}
	}
	return ca, nil
}

// loadOrCreateCA loads the delegation CA from varRoot/ssh/, or generates
// and persists a new one if absent.
func loadOrCreateCA(varRoot string, logf logger.Logf) (*delegationCA, error) {
	dir := filepath.Join(varRoot, "ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, caPrivateFileName)
	if b, err := os.ReadFile(path); err == nil {
		return delegationCAFromPrivate(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	logf("tailssh: generating new delegation CA")
	ca, err := newDelegationCA()
	if err != nil {
		return nil, err
	}
	priv, err := marshalCAPrivate(ca)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0600); err != nil {
		return nil, err
	}
	return ca, nil
}

// dropInConfig returns the contents of sshd_config.d\tailscale.conf.
//
// The TrustedUserCAKeys path uses forward slashes; OpenSSH for Windows
// accepts either separator.
func dropInConfig(caPubPath string) []byte {
	p := filepath.ToSlash(caPubPath)
	return []byte("# Managed by Tailscale - do not edit.\n" +
		"# Removing this file disables Tailscale-SSH delegation.\n" +
		"TrustedUserCAKeys \"" + p + "\"\n")
}

// ensureIncludeDirective makes sure mainConfig contains an Include directive
// for sshd_config.d\*.conf. Returns whether the file was modified.
//
// The directive is wrapped in a marker block so it can be recognized and
// kept idempotent across runs. Existing manual Include directives (without
// our markers) are also respected — if any Include of "sshd_config.d/*.conf"
// or "sshd_config.d\*.conf" is already present we leave the file alone.
func ensureIncludeDirective(mainConfig string) (changed bool, err error) {
	body, err := os.ReadFile(mainConfig)
	if err != nil {
		return false, err
	}
	if hasIncludeDirective(body) {
		return false, nil
	}
	block := "\n" + tailscaleBeginMarker + "\n" +
		"Include sshd_config.d\\*.conf\n" +
		tailscaleEndMarker + "\n"
	out := append(append([]byte(nil), body...), []byte(block)...)
	if err := writeAtomic(mainConfig, out, 0644); err != nil {
		return false, err
	}
	return true, nil
}

// hasIncludeDirective reports whether body already contains an active
// Include directive covering sshd_config.d\*.conf or our managed block.
func hasIncludeDirective(body []byte) bool {
	if bytes.Contains(body, []byte(tailscaleBeginMarker)) {
		return true
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		s := bytes.TrimSpace(line)
		if len(s) == 0 || s[0] == '#' {
			continue
		}
		// Case-insensitive prefix match on "Include".
		if len(s) < len("Include ") {
			continue
		}
		if !bytes.EqualFold(s[:len("Include")], []byte("Include")) {
			continue
		}
		rest := bytes.TrimSpace(s[len("Include"):])
		// Strip optional quotes.
		rest = bytes.Trim(rest, `"`)
		// Accept either separator since OpenSSH-for-Windows handles both.
		norm := bytes.ReplaceAll(rest, []byte("\\"), []byte("/"))
		if bytes.Contains(norm, []byte("sshd_config.d/")) {
			return true
		}
	}
	return false
}

// writeIfChanged writes data to path with mode iff the existing contents
// differ. Used to keep file mtimes stable when nothing has changed.
func writeIfChanged(path string, data []byte, mode os.FileMode) error {
	_, err := writeIfChangedReport(path, data, mode)
	return err
}

func writeIfChangedReport(path string, data []byte, mode os.FileMode) (changed bool, err error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return false, nil
	}
	return true, writeAtomic(path, data, mode)
}

// writeAtomic writes data to a tempfile in the same directory then renames
// it over path, so readers (including the running sshd) never see a
// half-written file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tailscale-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// requireSSHDService verifies that the sshd service is registered with
// the Service Control Manager. It does not check whether the service is
// running.
func requireSSHDService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService("sshd")
	if err != nil {
		// ERROR_SERVICE_DOES_NOT_EXIST (1060) is what we get when the
		// OpenSSH Server optional component is not installed.
		return errOpenSSHNotInstalled
	}
	s.Close()
	return nil
}

// startSSHD starts the sshd service if it is not already running and
// waits until it reports Running.
func startSSHD(logf logger.Logf) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService("sshd")
	if err != nil {
		return fmt.Errorf("open service sshd: %w", err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query sshd: %w", err)
	}
	if status.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start sshd: %w", err)
	}
	if err := waitForState(s, svc.Running, 30*time.Second); err != nil {
		return fmt.Errorf("wait for sshd start: %w", err)
	}
	logf("tailssh: sshd started")
	return nil
}

// restartSSHD stops and starts the local Windows OpenSSH service.
func restartSSHD(logf logger.Logf) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("sshd")
	if err != nil {
		return fmt.Errorf("open service sshd: %w", err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query sshd: %w", err)
	}
	if status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop sshd: %w", err)
		}
		if err := waitForState(s, svc.Stopped, 10*time.Second); err != nil {
			return fmt.Errorf("wait for sshd stop: %w", err)
		}
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start sshd: %w", err)
	}
	if err := waitForState(s, svc.Running, 30*time.Second); err != nil {
		return fmt.Errorf("wait for sshd start: %w", err)
	}
	logf("tailssh: sshd restarted")
	return nil
}

func waitForState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for state %v (last=%v)", want, status.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
