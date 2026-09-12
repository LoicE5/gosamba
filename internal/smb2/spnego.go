package smb2

import (
	"bytes"
	"errors"
)

// NegotiateSecurityBlob is the SPNEGO NegTokenInit2 advertising NTLMSSP only.
// Hardcoded because we never offer Kerberos and the structure is fixed.
//
// ASN.1 layout (DER):
//
//	[APPLICATION 0] (length 28) {
//	  OID 1.3.6.1.5.5.2 (SPNEGO),
//	  [0] (length 18) NegTokenInit {
//	    SEQUENCE (length 16) {
//	      [0] mechTypes (length 14) SEQUENCE OF OID (length 12) {
//	        OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
//	      }
//	    }
//	  }
//	}
//
// Total: 30 bytes.
var NegotiateSecurityBlob = []byte{
	0x60, 0x1c,
	0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
	0xa0, 0x12,
	0x30, 0x10,
	0xa0, 0x0e,
	0x30, 0x0c,
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
}

// ntlmsspMagic is the start of every NTLMSSP message.
var ntlmsspMagic = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// UnwrapNTLM returns the NTLMSSP message carried by a SESSION_SETUP security
// buffer.
//
// The blob is parsed as SPNEGO first and the mechToken / responseToken is
// returned exactly, with nothing before or after it. Getting the end of the
// message right matters as much as the start: these bytes are hashed into the
// NTLMSSP MIC (MS-NLMP §3.1.5.1.2), so any trailing DER — a mechListMIC after
// the token, most obviously — would make every MIC mismatch. Scanning for the
// NTLMSSP signature, which is what this used to do, can only find the start;
// it returned everything from there to the end of the blob and so depended on
// the token happening to be the last element.
//
// A blob that is not parseable SPNEGO falls back to that scan: some clients put
// a bare NTLMSSP message in the security buffer, and for those the blob is the
// message.
func UnwrapNTLM(blob []byte) ([]byte, error) {
	if tok, ok := spnegoInnerToken(blob); ok && bytes.HasPrefix(tok, ntlmsspMagic) {
		return tok, nil
	}
	idx := bytes.Index(blob, ntlmsspMagic)
	if idx < 0 {
		return nil, errors.New("smb2: NTLMSSP message not found in SPNEGO blob")
	}
	return blob[idx:], nil
}

// spnegoInnerToken extracts the [2] element (mechToken of a NegTokenInit, or
// responseToken of a NegTokenResp) from a SPNEGO token.
//
//	NegTokenInit  ::= [APPLICATION 0] SEQUENCE { OID, [0] SEQUENCE { ... [2] OCTET STRING ... } }
//	NegTokenResp  ::= [1] SEQUENCE { ... [2] OCTET STRING ... }
//
// Every element of both SEQUENCEs is OPTIONAL and context-tagged, so walking
// the sequence for tag [2] handles NegTokenInit, Microsoft's NegTokenInit2
// (which adds a negHints [3]) and NegTokenResp alike. Anything malformed,
// unexpected or absent reports false and leaves the caller to fall back.
func spnegoInnerToken(blob []byte) ([]byte, bool) {
	tag, content, _, ok := derTLV(blob)
	if !ok {
		return nil, false
	}
	var seq []byte
	switch tag {
	case 0x60: // [APPLICATION 0] — GSS-API InitialContextToken wrapping NegTokenInit
		t, _, rest, ok := derTLV(content)
		if !ok || t != 0x06 { // thisMech OID (SPNEGO)
			return nil, false
		}
		t, negTokenInit, _, ok := derTLV(rest)
		if !ok || t != 0xa0 { // [0] NegTokenInit
			return nil, false
		}
		t, inner, _, ok := derTLV(negTokenInit)
		if !ok || t != 0x30 { // SEQUENCE
			return nil, false
		}
		seq = inner
	case 0xa1: // [1] NegTokenResp
		t, inner, _, ok := derTLV(content)
		if !ok || t != 0x30 { // SEQUENCE
			return nil, false
		}
		seq = inner
	default:
		return nil, false
	}

	for len(seq) > 0 {
		t, c, rest, ok := derTLV(seq)
		if !ok {
			return nil, false
		}
		if t == 0xa2 { // [2] mechToken / responseToken
			it, token, _, ok := derTLV(c)
			if !ok || it != 0x04 { // OCTET STRING
				return nil, false
			}
			return token, true
		}
		seq = rest
	}
	return nil, false
}

// derTLV splits one DER tag-length-value off the front of b, returning the tag,
// its content and whatever follows. Only what SPNEGO uses is accepted:
// single-byte tags and definite lengths. Indefinite length (BER, not DER), a
// multi-byte tag, or a length running past the buffer all report false rather
// than guessing.
func derTLV(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, false
	}
	i := 1
	length := int(b[i])
	i++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 3 || len(b) < i+n {
			// n == 0 is indefinite length; anything past 3 bytes describes a
			// token far larger than a SESSION_SETUP security buffer can hold.
			return 0, nil, nil, false
		}
		length = 0
		for j := 0; j < n; j++ {
			length = length<<8 | int(b[i+j])
		}
		i += n
	}
	if length > len(b)-i {
		return 0, nil, nil, false
	}
	return tag, b[i : i+length], b[i+length:], true
}

// SPNEGOState identifies negTokenResp.negState.
type SPNEGOState byte

const (
	SPNEGOAcceptCompleted  SPNEGOState = 0x00
	SPNEGOAcceptIncomplete SPNEGOState = 0x01
)

// ntlmsspOID is the DER-encoded NTLMSSP object identifier (1.3.6.1.4.1.311.2.2.10).
var ntlmsspOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// WrapNTLMResp builds a SPNEGO negTokenResp containing the NTLM payload.
// includeSupportedMech: set to true on the first response (Type 2 / challenge);
// omit on subsequent (acceptCompleted) responses.
func WrapNTLMResp(state SPNEGOState, ntlm []byte) []byte {
	includeSupportedMech := state == SPNEGOAcceptIncomplete

	negStateBytes := wrapTLV(0x0a, []byte{byte(state)})
	seqContents := wrapTLV(0xa0, negStateBytes)
	if includeSupportedMech {
		// supportedMech [1] OID = NTLMSSP
		seqContents = append(seqContents, wrapTLV(0xa1, ntlmsspOID)...)
	}
	if len(ntlm) > 0 {
		innerOctet := wrapTLV(0x04, ntlm)
		respToken := wrapTLV(0xa2, innerOctet)
		seqContents = append(seqContents, respToken...)
	}
	seq := wrapTLV(0x30, seqContents)
	return wrapTLV(0xa1, seq)
}

func wrapTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch {
	case len(content) < 0x80:
		out = append(out, byte(len(content)))
	case len(content) < 0x100:
		out = append(out, 0x81, byte(len(content)))
	case len(content) < 0x10000:
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	default:
		out = append(out, 0x83, byte(len(content)>>16), byte(len(content)>>8), byte(len(content)))
	}
	out = append(out, content...)
	return out
}
