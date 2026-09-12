package smb2

import "errors"

var (
	ErrNoCommonDialect     = errors.New("smb2: no common dialect")
	ErrNoCommonCipher      = errors.New("smb2: no common encryption cipher")
	ErrNoPreauthSHA512     = errors.New("smb2: client did not advertise SHA-512 preauth")
	ErrNoCommonSigningAlgo = errors.New("smb2: no common signing algorithm")
)

// Selection holds the algorithms the server has chosen for this connection.
type Selection struct {
	Dialect     Dialect
	Cipher      Cipher // 0 if encryption disabled
	Hash        Hash
	SigningAlgo SigningAlgo
}

// SupportedDialects, in server-preference order. We prefer 3.1.1 (preauth +
// negotiate-context cryptography) and fall back through the older 3.x and 2.x
// dialects so that clients that don't speak 3.1.1 can still connect.
var SupportedDialects = []Dialect{Dialect311, Dialect302, Dialect300, Dialect210, Dialect202}

// SupportedCiphers, server preference order. Preferring AES-256-GCM means the
// session keys must be derived at 256 bits (MS-SMB2 §3.1.4.2 uses L=256 for the
// AES-256 ciphers); see smb3.CipherKeyBits and its use in the session-setup
// key derivation.
//
// All four MS-SMB2 ciphers are listed. AES-256-CCM in particular must not be
// left out: macOS offers it, and a client configured to offer *only* that
// cipher would otherwise select nothing here, which makes the negotiate
// response omit the encryption context entirely. The client does not check for
// that omission — it keeps its own default of AES-128-CCM — so the two ends end
// up disagreeing on the cipher and the connection dies on the first transform
// frame. Advertising every cipher we can actually perform removes the silent
// mismatch.
var SupportedCiphers = []Cipher{CipherAES256GCM, CipherAES128GCM, CipherAES256CCM, CipherAES128CCM}

// SupportedSigningAlgos, server preference order. CMAC first because GMAC nonce
// construction (related-op bit, server-to-client bit per MS-SMB2 §3.1.4.1) has
// quirks our impl hasn't fully validated against Windows/macOS yet.
//
// There is also a cryptographic reason to keep CMAC ahead of GMAC. The GMAC
// nonce is fully determined by (MessageId, Flags & (SERVER_TO_REDIR|ASYNC)), so
// an async command that emits an interim STATUS_PENDING and then a final
// response — CHANGE_NOTIFY always does — signs two different messages under the
// same key *and* the same GCM nonce. That is a forbidden-attack setup: the two
// tags together disclose the GHASH subkey. The nonce derivation is what the
// spec mandates (Windows and Samba build it identically), so it cannot be fixed
// unilaterally without breaking signature verification on every real client;
// choosing CMAC, which is nonce-free, avoids the situation instead.
var SupportedSigningAlgos = []SigningAlgo{SigningAESCMAC, SigningAESGMAC}

// Select chooses dialect/cipher/signing for this connection.
// requireEncryption: when true, return ErrNoCommonCipher if no overlap.
func Select(req NegotiateRequest, requireEncryption bool) (Selection, error) {
	var sel Selection

	dlOK := false
DialectLoop:
	for _, d := range SupportedDialects {
		for _, c := range req.Dialects {
			if c == d {
				sel.Dialect = d
				dlOK = true
				break DialectLoop
			}
		}
	}
	if !dlOK {
		return Selection{}, ErrNoCommonDialect
	}

	// Preauth-integrity context is only present (and required) for 3.1.1.
	if sel.Dialect == Dialect311 {
		gotSHA := false
		for _, h := range req.PreauthIntegrity.HashAlgorithms {
			if h == HashSHA512 {
				gotSHA = true
				break
			}
		}
		if !gotSHA {
			return Selection{}, ErrNoPreauthSHA512
		}
		sel.Hash = HashSHA512
	}

	// Encryption: 3.1.1 advertises ciphers in a NegotiateContext; 3.0/3.0.2
	// signal encryption via SMB2_GLOBAL_CAP_ENCRYPTION and use AES-128-CCM.
	// 2.x doesn't support encryption.
	switch sel.Dialect {
	case Dialect311:
		if req.Encryption != nil {
			for _, sc := range SupportedCiphers {
				for _, cc := range req.Encryption.Ciphers {
					if sc == cc {
						sel.Cipher = sc
						break
					}
				}
				if sel.Cipher != 0 {
					break
				}
			}
		}
	case Dialect300, Dialect302:
		if req.Capabilities&CapEncryption != 0 {
			sel.Cipher = CipherAES128CCM
		}
	}
	if requireEncryption && sel.Cipher == 0 {
		return Selection{}, ErrNoCommonCipher
	}

	switch sel.Dialect {
	case Dialect311:
		if req.SigningCaps != nil && len(req.SigningCaps.Algorithms) > 0 {
			for _, ss := range SupportedSigningAlgos {
				for _, cs := range req.SigningCaps.Algorithms {
					if ss == cs {
						sel.SigningAlgo = ss
						break
					}
				}
				if sel.SigningAlgo != 0 {
					break
				}
			}
			if sel.SigningAlgo == 0 {
				return Selection{}, ErrNoCommonSigningAlgo
			}
		} else {
			sel.SigningAlgo = SigningAESCMAC
		}
	case Dialect300, Dialect302:
		sel.SigningAlgo = SigningAESCMAC
	default:
		// 2.0.2 / 2.1: HMAC-SHA256.
		sel.SigningAlgo = SigningHMACSHA256
	}

	return sel, nil
}
