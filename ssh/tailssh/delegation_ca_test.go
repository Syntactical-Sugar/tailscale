// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9 || windows

package tailssh

import (
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDelegationCA_MintUserCert(t *testing.T) {
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ca.MintUserCert("alice", 30*time.Second)
	if err != nil {
		t.Fatalf("MintUserCert: %v", err)
	}

	pub := signer.PublicKey()
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("signer public key is %T, want *ssh.Certificate", pub)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %v, want UserCert", cert.CertType)
	}
	if !slices.Equal(cert.ValidPrincipals, []string{"alice"}) {
		t.Errorf("ValidPrincipals = %v, want [alice]", cert.ValidPrincipals)
	}
	if cert.KeyId != "tailscale-ssh-delegation:alice" {
		t.Errorf("KeyId = %q", cert.KeyId)
	}
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now {
		t.Errorf("ValidAfter %v > now %v", cert.ValidAfter, now)
	}
	if cert.ValidBefore <= now {
		t.Errorf("ValidBefore %v <= now %v", cert.ValidBefore, now)
	}
	if cert.ValidBefore-now > 60 {
		t.Errorf("ValidBefore too far in future: %v vs now %v", cert.ValidBefore, now)
	}

	// Verify the certificate signature is by our CA.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(ca.signer.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("CheckCert as alice: %v", err)
	}
	if err := checker.CheckCert("bob", cert); err == nil {
		t.Errorf("CheckCert as bob unexpectedly succeeded")
	}
}

func TestDelegationCA_PermitExtensions(t *testing.T) {
	// Without the permit-pty extension OpenSSH refuses pty-req with
	// "Allocating a pty not permitted for this connection." Make sure
	// every minted cert carries the standard set.
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ca.MintUserCert("alice", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cert := sig.PublicKey().(*ssh.Certificate)
	for _, ext := range []string{
		"permit-pty",
		"permit-X11-forwarding",
		"permit-agent-forwarding",
		"permit-port-forwarding",
		"permit-user-rc",
	} {
		if _, ok := cert.Permissions.Extensions[ext]; !ok {
			t.Errorf("cert missing extension %q; have %v", ext, cert.Permissions.Extensions)
		}
	}
}

func TestDelegationCA_SignatureKey(t *testing.T) {
	// Two CAs with different keys produce certificates whose SignatureKey
	// fields point at each respective CA. Authority checks (e.g. in
	// CertChecker.IsUserAuthority during ssh user-auth) rely on this.
	ca1, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}

	sig1, err := ca1.MintUserCert("alice", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cert1 := sig1.PublicKey().(*ssh.Certificate)

	if string(cert1.SignatureKey.Marshal()) != string(ca1.signer.PublicKey().Marshal()) {
		t.Error("cert1.SignatureKey does not match CA1's public key")
	}
	if string(cert1.SignatureKey.Marshal()) == string(ca2.signer.PublicKey().Marshal()) {
		t.Error("cert1.SignatureKey unexpectedly matches CA2's public key")
	}
}

func TestDelegationCA_EmptyPrincipal(t *testing.T) {
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.MintUserCert("", 30*time.Second); err == nil {
		t.Error("MintUserCert with empty principal: want error, got nil")
	}
}

func TestDelegationCA_NonPositiveValidity(t *testing.T) {
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.MintUserCert("alice", 0); err == nil {
		t.Error("MintUserCert with zero validity: want error, got nil")
	}
}

func TestDelegationCA_PersistRoundTrip(t *testing.T) {
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := marshalCAPrivate(ca)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := delegationCAFromPrivate(priv)
	if err != nil {
		t.Fatalf("delegationCAFromPrivate: %v", err)
	}
	if string(ca.signer.PublicKey().Marshal()) != string(ca2.signer.PublicKey().Marshal()) {
		t.Error("public key changed across round-trip")
	}

	sig, err := ca2.MintUserCert("alice", 30*time.Second)
	if err != nil {
		t.Fatalf("MintUserCert after reload: %v", err)
	}
	cert := sig.PublicKey().(*ssh.Certificate)
	if string(cert.SignatureKey.Marshal()) != string(ca.signer.PublicKey().Marshal()) {
		t.Error("reloaded CA signed cert with different key than original")
	}
}

func TestDelegationCA_PublicKey(t *testing.T) {
	ca, err := newDelegationCA()
	if err != nil {
		t.Fatal(err)
	}
	pub := ca.PublicKey()
	if len(pub) == 0 {
		t.Fatal("PublicKey returned empty bytes")
	}
	if pub[len(pub)-1] != '\n' {
		t.Errorf("PublicKey not newline-terminated: %q", pub)
	}
	// Parse back as authorized_keys to confirm format.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if string(parsed.Marshal()) != string(ca.signer.PublicKey().Marshal()) {
		t.Error("round-tripped public key does not match CA's signer key")
	}
}
