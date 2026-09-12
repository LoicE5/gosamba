package smb2

import (
	"bytes"
	"testing"
)

// --- UnwrapNTLM must return the token, not the tail of the blob -------------
//
// UnwrapNTLM used to return blob[idx:] — everything from the NTLMSSP signature
// to the end of the SPNEGO token. Those bytes are hashed into the NTLMSSP MIC,
// so anything DER put after the token (a mechListMIC, most obviously) would
// make every MIC mismatch. It only worked because the mechToken happened to be
// the last element of a NegTokenInit.

// derTag wraps content in a DER tag-length-value using the same length rules
// the encoder must produce.
func derTag(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch {
	case len(content) < 0x80:
		out = append(out, byte(len(content)))
	case len(content) < 0x100:
		out = append(out, 0x81, byte(len(content)))
	default:
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	return append(out, content...)
}

// negTokenInit builds a SPNEGO NegTokenInit carrying mechToken, optionally
// followed by a mechListMIC — the trailing DER that used to poison the hash.
func negTokenInit(mechToken, mechListMIC []byte) []byte {
	mechTypes := derTag(0xa0, derTag(0x30, ntlmsspOID))
	inner := append([]byte(nil), mechTypes...)
	inner = append(inner, derTag(0xa2, derTag(0x04, mechToken))...)
	if len(mechListMIC) > 0 {
		inner = append(inner, derTag(0xa3, derTag(0x04, mechListMIC))...)
	}
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	body := append(append([]byte(nil), spnegoOID...), derTag(0xa0, derTag(0x30, inner))...)
	return derTag(0x60, body)
}

func fakeNTLM(msgType byte, size int) []byte {
	msg := make([]byte, size)
	copy(msg, []byte("NTLMSSP\x00"))
	msg[8] = msgType
	for i := 12; i < size; i++ {
		msg[i] = byte(i)
	}
	return msg
}

// TestFixSPNEGO_TrimsTypeOneMechToken is the regression test: the type-1
// message must come back with nothing appended, even when the NegTokenInit
// carries a mechListMIC after the mechToken.
func TestFixSPNEGO_TrimsTypeOneMechToken(t *testing.T) {
	type1 := fakeNTLM(0x01, 40)
	mic := bytes.Repeat([]byte{0x5E}, 16)

	for _, tail := range [][]byte{nil, mic} {
		got, err := UnwrapNTLM(negTokenInit(type1, tail))
		if err != nil {
			t.Fatalf("tail=%d: %v", len(tail), err)
		}
		if !bytes.Equal(got, type1) {
			t.Fatalf("tail=%d: got %d bytes (%x), want exactly the %d-byte NEGOTIATE_MESSAGE",
				len(tail), len(got), got, len(type1))
		}
	}
}

// TestFixSPNEGO_TrimsResponseToken covers the other leg: a negTokenResp whose
// responseToken is followed by a mechListMIC, which is what a real client's
// type-3 looks like.
func TestFixSPNEGO_TrimsResponseToken(t *testing.T) {
	type3 := fakeNTLM(0x03, 120)
	inner := derTag(0xa0, []byte{0x0a, 0x01, 0x01}) // negState
	inner = append(inner, derTag(0xa2, derTag(0x04, type3))...)
	inner = append(inner, derTag(0xa3, derTag(0x04, bytes.Repeat([]byte{0x77}, 16)))...)
	blob := derTag(0xa1, derTag(0x30, inner))

	got, err := UnwrapNTLM(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, type3) {
		t.Fatalf("got %d bytes, want exactly the %d-byte AUTHENTICATE_MESSAGE", len(got), len(type3))
	}
}

// TestFixSPNEGO_LongFormLengths exercises the multi-byte DER lengths a real
// type-3 (well over 127 bytes) forces the parser through.
func TestFixSPNEGO_LongFormLengths(t *testing.T) {
	for _, size := range []int{40, 128, 300, 1024} {
		msg := fakeNTLM(0x03, size)
		got, err := UnwrapNTLM(negTokenInit(msg, bytes.Repeat([]byte{0x01}, 16)))
		if err != nil {
			t.Fatalf("size=%d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size=%d: got %d bytes, want %d", size, len(got), size)
		}
	}
}

// TestFixSPNEGO_RoundTripsOwnWrapper keeps our own encoder and the parser in
// agreement — WrapNTLMResp is what the server sends back.
func TestFixSPNEGO_RoundTripsOwnWrapper(t *testing.T) {
	type2 := fakeNTLM(0x02, 200)
	got, err := UnwrapNTLM(WrapNTLMResp(SPNEGOAcceptIncomplete, type2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, type2) {
		t.Fatalf("got %d bytes, want %d", len(got), len(type2))
	}
}

// TestFixSPNEGO_FallbackForBareAndMalformed keeps the old behaviour where it is
// still needed: a security buffer holding a bare NTLMSSP message, and anything
// that does not parse as SPNEGO, must still yield the message.
func TestFixSPNEGO_FallbackForBareAndMalformed(t *testing.T) {
	msg := fakeNTLM(0x01, 40)

	got, err := UnwrapNTLM(msg)
	if err != nil {
		t.Fatalf("bare NTLMSSP: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Error("bare NTLMSSP message was not returned verbatim")
	}

	// Truncated DER: the declared length runs past the buffer.
	broken := append([]byte{0x60, 0x7f}, msg...)
	got, err = UnwrapNTLM(broken)
	if err != nil {
		t.Fatalf("malformed DER: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Error("malformed DER did not fall back to the signature scan")
	}

	if _, err := UnwrapNTLM([]byte{0x60, 0x02, 0xAA, 0xBB}); err == nil {
		t.Error("a blob with no NTLMSSP message anywhere should be an error")
	}
}

// TestFixSPNEGO_DERParserRejectsGarbage pins the parser's refusal cases so a
// hostile security buffer cannot walk it out of bounds or into a loop.
func TestFixSPNEGO_DERParserRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x60},
		{0x60, 0x80},                   // indefinite length (BER, not DER)
		{0x60, 0x85, 1, 2, 3, 4, 5},    // length-of-length too large
		{0x60, 0x82, 0xFF, 0xFF, 0x01}, // length past the end of the buffer
		{0x1f, 0x02, 0x01, 0x02},       // multi-byte tag
		{0xa1, 0x02, 0x30, 0x00},       // NegTokenResp with an empty sequence
	}
	for i, c := range cases {
		if tok, ok := spnegoInnerToken(c); ok {
			t.Errorf("case %d: parser accepted %x and returned %x", i, c, tok)
		}
	}
}
