package smb3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// --- AES-256-CCM (cipher id 0x0003) ----------------------------------------
//
// AES-256-CCM was missing from smb2.SupportedCiphers, so a client that offers
// only that cipher negotiated nothing at all: the server left the encryption
// context out of the negotiate response, the client silently kept its own
// default of AES-128-CCM, and the connection died on the first transform frame.
// Enabling it is only safe if the CCM code really handles a 256-bit key, which
// is what the cross-checks below establish — a round trip against ourselves
// would pass even for a CCM that is symmetrically wrong.

// refCCMSeal is an independent AES-CCM (NIST SP 800-38C) encryption for the
// parameters SMB3 uses: 11-byte nonce (so L = 15-11 = 4), 16-byte tag. It is
// deliberately built out of the standard library's CBC and CTR modes rather
// than reusing anything from ccm.go, so agreement between the two is evidence
// about the implementation and not just about the test.
func refCCMSeal(t *testing.T, key, nonce, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher(%d-byte key): %v", len(key), err)
	}
	const (
		tagLen = 16
		l      = 4 // length-of-length; nonce is 15-l = 11 bytes
	)
	if len(nonce) != 15-l {
		t.Fatalf("reference CCM wants an %d-byte nonce, got %d", 15-l, len(nonce))
	}

	// B0 = flags || nonce || Q  (SP 800-38C §A.2.1)
	flags := byte(l - 1)
	flags |= byte((tagLen - 2) / 2 << 3)
	if len(aad) > 0 {
		flags |= 0x40
	}
	b0 := make([]byte, 16)
	b0[0] = flags
	copy(b0[1:], nonce)
	binary.BigEndian.PutUint32(b0[12:], uint32(len(plaintext)))

	// The CBC-MAC input: B0 || encoded-AAD (zero padded) || plaintext (zero padded).
	macIn := append([]byte(nil), b0...)
	if len(aad) > 0 {
		if len(aad) >= 0xFF00 {
			t.Fatalf("reference CCM only encodes short AAD, got %d bytes", len(aad))
		}
		enc := []byte{byte(len(aad) >> 8), byte(len(aad))}
		enc = append(enc, aad...)
		for len(enc)%16 != 0 {
			enc = append(enc, 0)
		}
		macIn = append(macIn, enc...)
	}
	if len(plaintext) > 0 {
		pad := append([]byte(nil), plaintext...)
		for len(pad)%16 != 0 {
			pad = append(pad, 0)
		}
		macIn = append(macIn, pad...)
	}
	macOut := make([]byte, len(macIn))
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(macOut, macIn)
	tag := macOut[len(macOut)-16:] // T = last CBC block

	// Counter block 0 encrypts the tag; the keystream for the payload starts at
	// counter block 1.
	ctr0 := make([]byte, 16)
	ctr0[0] = byte(l - 1)
	copy(ctr0[1:], nonce)
	s0 := make([]byte, 16)
	block.Encrypt(s0, ctr0)

	ctr1 := append([]byte(nil), ctr0...)
	binary.BigEndian.PutUint32(ctr1[12:], 1)
	out := make([]byte, len(plaintext)+tagLen)
	cipher.NewCTR(block, ctr1).XORKeyStream(out[:len(plaintext)], plaintext)
	for i := 0; i < tagLen; i++ {
		out[len(plaintext)+i] = tag[i] ^ s0[i]
	}
	return out
}

// ccmCases are the shapes worth checking: empty, sub-block, exactly one block,
// straddling a block boundary, and multi-block — with and without AAD.
var ccmCases = []struct {
	name  string
	ptLen int
	adLen int
}{
	{"empty", 0, 0},
	{"empty-with-aad", 0, 32},
	{"one-byte", 1, 32},
	{"under-block", 15, 32},
	{"exact-block", 16, 32},
	{"over-block", 17, 32},
	{"multi-block", 1000, 32},
	{"no-aad", 64, 0},
	{"odd-aad", 64, 7},
}

func ccmFill(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed ^ byte(i*7+1)
	}
	return b
}

// TestFixCCM_MatchesReference_256BitKey is the evidence that enabling
// AES-256-CCM is safe: our CCM must produce byte-identical output to an
// independent implementation of SP 800-38C when keyed with 32 bytes.
func TestFixCCM_MatchesReference_256BitKey(t *testing.T) {
	for _, keyLen := range []int{16, 32} {
		key := ccmFill(keyLen, 0xA5)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		aead, err := newCCM(block)
		if err != nil {
			t.Fatalf("newCCM(%d-byte key): %v", keyLen, err)
		}
		if aead.NonceSize() != ccmNonceSize || aead.Overhead() != ccmTagSize {
			t.Fatalf("nonce/overhead = %d/%d", aead.NonceSize(), aead.Overhead())
		}
		for _, c := range ccmCases {
			nonce := ccmFill(ccmNonceSize, byte(c.ptLen))
			pt := ccmFill(c.ptLen, 0x11)
			aad := ccmFill(c.adLen, 0x22)

			got := aead.Seal(nil, nonce, pt, aad)
			want := refCCMSeal(t, key, nonce, pt, aad)
			if !bytes.Equal(got, want) {
				t.Fatalf("key=%d %s: Seal mismatch\n got %x\nwant %x", keyLen*8, c.name, got, want)
			}

			// And the other direction: our Open must accept the reference's
			// ciphertext and give back the original plaintext.
			back, err := aead.Open(nil, nonce, want, aad)
			if err != nil {
				t.Fatalf("key=%d %s: Open(reference ciphertext): %v", keyLen*8, c.name, err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("key=%d %s: Open returned %x, want %x", keyLen*8, c.name, back, pt)
			}
		}
	}
}

// TestFixCCM_AES256RejectsTamperingAndWrongKey checks the authentication half
// at 256 bits: a flipped bit anywhere, or the wrong key, must fail rather than
// return garbage plaintext.
func TestFixCCM_AES256RejectsTamperingAndWrongKey(t *testing.T) {
	key := ccmFill(32, 0x5A)
	block, _ := aes.NewCipher(key)
	aead, err := newCCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := ccmFill(ccmNonceSize, 0x01)
	pt := []byte("an SMB3 message encrypted under a 256-bit CCM key")
	aad := ccmFill(32, 0x33)
	ct := aead.Seal(nil, nonce, pt, aad)

	for _, pos := range []int{0, len(pt) / 2, len(pt) - 1, len(ct) - 1} {
		bad := append([]byte(nil), ct...)
		bad[pos] ^= 0x01
		if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
			t.Errorf("byte %d flipped and Open still succeeded", pos)
		}
	}
	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, badAAD); err == nil {
		t.Error("Open accepted a modified AAD")
	}
	otherKey := ccmFill(32, 0x5B)
	otherBlock, _ := aes.NewCipher(otherKey)
	other, err := newCCM(otherBlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(nil, nonce, ct, aad); err == nil {
		t.Error("Open accepted a frame sealed under a different key")
	}
}

// TestFixCCM_TransformRoundTripAES256CCM exercises the cipher exactly as a
// negotiated session does: key derived at the length CipherKeyBits demands,
// then a full transform-header round trip.
func TestFixCCM_TransformRoundTripAES256CCM(t *testing.T) {
	if CipherKeyBits(CipherAES256CCM) != 256 {
		t.Fatalf("CipherKeyBits(AES256CCM) = %d, want 256", CipherKeyBits(CipherAES256CCM))
	}
	sessionKey := ccmFill(16, 0x7C)
	preauth := ccmFill(64, 0x2D)
	key := KDF(sessionKey, []byte("SMBC2SCipherKey\x00"), preauth, CipherKeyBits(CipherAES256CCM))
	if len(key) != 32 {
		t.Fatalf("derived key is %d bytes, want 32", len(key))
	}

	for _, size := range []int{0, 1, 64, 70000} {
		plain := ccmFill(size, 0x44)
		frame, err := EncryptTransform(CipherAES256CCM, key, 0x1122334455667788, plain)
		if err != nil {
			t.Fatalf("size=%d: EncryptTransform: %v", size, err)
		}
		if !IsTransform(frame) {
			t.Fatalf("size=%d: frame is not a transform frame", size)
		}
		got, sid, err := DecryptTransform(CipherAES256CCM, key, frame)
		if err != nil {
			t.Fatalf("size=%d: DecryptTransform: %v", size, err)
		}
		if sid != 0x1122334455667788 {
			t.Errorf("size=%d: session id %x", size, sid)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("size=%d: plaintext round trip mismatch", size)
		}
		// A 128-bit key must not be accepted for a 256-bit cipher.
		if _, err := EncryptTransform(CipherAES256CCM, key[:16], 1, plain); err == nil {
			t.Errorf("size=%d: EncryptTransform accepted a 16-byte key for AES-256-CCM", size)
		}
	}
}
