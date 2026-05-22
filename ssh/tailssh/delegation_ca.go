// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9 || windows

package tailssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// delegationCA is an SSH certificate authority used by the Windows
// delegation backend. Tailscaled holds the private key; the local Windows
// OpenSSH server trusts the CA's public key via TrustedUserCAKeys in
// sshd_config. To open an inner session as a particular local user,
// tailscaled mints a short-lived user certificate naming that user as a
// principal.
//
// The CA is also useful in tests as a self-contained ssh-cert minter.
type delegationCA struct {
	signer ssh.Signer // signs certificates with the CA's private key
}

// newDelegationCA generates a fresh Ed25519 SSH CA keypair.
func newDelegationCA() (*delegationCA, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: generate: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: signer: %w", err)
	}
	return &delegationCA{signer: signer}, nil
}

// delegationCAFromPrivate constructs a delegationCA from a previously
// generated private key in OpenSSH PEM format. Used to reload a persisted
// CA at tailscaled startup.
func delegationCAFromPrivate(pem []byte) (*delegationCA, error) {
	k, err := ssh.ParseRawPrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: parse private: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: signer: %w", err)
	}
	return &delegationCA{signer: signer}, nil
}

// PublicKey returns the CA's public key in OpenSSH authorized_keys format
// (a single line ending in a newline). Suitable for writing into the file
// referenced by sshd_config's TrustedUserCAKeys directive.
func (ca *delegationCA) PublicKey() []byte {
	return ssh.MarshalAuthorizedKey(ca.signer.PublicKey())
}

// MintUserCert mints a short-lived user certificate authorizing a client
// to log in to local sshd as the given principal (Windows username).
//
// The returned certSigner is used as the AuthMethod when dialing the inner
// SSH connection; certPubBytes is the wire-format certificate that gets
// sent to sshd during user-auth. The certificate's private key is freshly
// generated for this session and never persisted.
func (ca *delegationCA) MintUserCert(principal string, validity time.Duration) (certSigner ssh.Signer, err error) {
	if principal == "" {
		return nil, errors.New("delegationCA: empty principal")
	}
	if validity <= 0 {
		return nil, errors.New("delegationCA: non-positive validity")
	}

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: user key: %w", err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	if err != nil {
		return nil, fmt.Errorf("delegationCA: user signer: %w", err)
	}

	var serialBytes [8]byte
	if _, err := rand.Read(serialBytes[:]); err != nil {
		return nil, fmt.Errorf("delegationCA: serial: %w", err)
	}
	serial := binary.BigEndian.Uint64(serialBytes[:])

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "tailscale-ssh-delegation:" + principal,
		Serial:          serial,
		ValidPrincipals: []string{principal},
		// Backdate slightly to absorb clock skew between tailscaled and
		// the local OpenSSH service.
		ValidAfter:  uint64(now.Add(-5 * time.Second).Unix()),
		ValidBefore: uint64(now.Add(validity).Unix()),
		Permissions: ssh.Permissions{
			// We dial loopback only; no need for source-address
			// restrictions, but no extensions either — minimal cert.
		},
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, fmt.Errorf("delegationCA: sign: %w", err)
	}
	return ssh.NewCertSigner(cert, userSigner)
}
