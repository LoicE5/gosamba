package smb2

import "testing"

// --- AES-256-CCM must be selectable -----------------------------------------
//
// SupportedCiphers used to list only AES256GCM, AES128GCM and AES128CCM. A
// client offering just AES-256-CCM (macOS offers the cipher, and can be
// configured to offer nothing else) therefore matched nothing: Select returned
// Cipher == 0, the negotiate response carried no encryption context at all, and
// the client kept its own default of AES-128-CCM. Nothing on the client side
// checks for that omission, so the two ends disagreed about the cipher and the
// server dropped the connection on the first transform frame.

func negotiateOffering(ciphers ...Cipher) NegotiateRequest {
	return NegotiateRequest{
		Dialects:         []Dialect{Dialect311},
		PreauthIntegrity: PreauthIntegrityContext{HashAlgorithms: []Hash{HashSHA512}},
		Encryption:       &EncryptionContext{Ciphers: ciphers},
	}
}

// TestFixNegotiate_SelectsAES256CCMWhenOnlyOffer is the regression test: the
// one cipher the client offers must be the one we select.
func TestFixNegotiate_SelectsAES256CCMWhenOnlyOffer(t *testing.T) {
	sel, err := Select(negotiateOffering(CipherAES256CCM), false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if sel.Cipher != CipherAES256CCM {
		t.Fatalf("cipher = 0x%04x, want 0x%04x (AES-256-CCM)", sel.Cipher, CipherAES256CCM)
	}
}

// TestFixNegotiate_EveryMSSMB2CipherIsSelectable walks all four cipher ids
// defined by MS-SMB2. Each one, offered alone, must be chosen — otherwise the
// silent-mismatch failure above comes back for that cipher.
func TestFixNegotiate_EveryMSSMB2CipherIsSelectable(t *testing.T) {
	for _, c := range []Cipher{CipherAES128CCM, CipherAES128GCM, CipherAES256CCM, CipherAES256GCM} {
		sel, err := Select(negotiateOffering(c), true)
		if err != nil {
			t.Errorf("cipher 0x%04x offered alone: %v", c, err)
			continue
		}
		if sel.Cipher != c {
			t.Errorf("cipher 0x%04x offered alone: selected 0x%04x", c, sel.Cipher)
		}
	}
}

// TestFixNegotiate_PreferenceOrderUnchanged pins the order so that adding
// AES-256-CCM did not quietly demote the GCM ciphers, which are what Windows
// picks and what we want picked when there is a choice.
func TestFixNegotiate_PreferenceOrderUnchanged(t *testing.T) {
	all := []Cipher{CipherAES128CCM, CipherAES128GCM, CipherAES256CCM, CipherAES256GCM}
	cases := []struct {
		offer []Cipher
		want  Cipher
	}{
		{all, CipherAES256GCM},
		{[]Cipher{CipherAES128CCM, CipherAES128GCM, CipherAES256CCM}, CipherAES128GCM},
		{[]Cipher{CipherAES128CCM, CipherAES256CCM}, CipherAES256CCM},
		{[]Cipher{CipherAES128CCM}, CipherAES128CCM},
	}
	for _, c := range cases {
		sel, err := Select(negotiateOffering(c.offer...), true)
		if err != nil {
			t.Errorf("offer %v: %v", c.offer, err)
			continue
		}
		if sel.Cipher != c.want {
			t.Errorf("offer %v: selected 0x%04x, want 0x%04x", c.offer, sel.Cipher, c.want)
		}
	}
}

// TestFixNegotiate_UnknownCipherStillRefused guards the other direction: a
// cipher we cannot perform must not be selected just because the list grew.
func TestFixNegotiate_UnknownCipherStillRefused(t *testing.T) {
	sel, err := Select(negotiateOffering(Cipher(0x00FF)), false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if sel.Cipher != 0 {
		t.Fatalf("selected unknown cipher 0x%04x", sel.Cipher)
	}
	if _, err := Select(negotiateOffering(Cipher(0x00FF)), true); err != ErrNoCommonCipher {
		t.Fatalf("requireEncryption with no common cipher: err = %v, want ErrNoCommonCipher", err)
	}
}
