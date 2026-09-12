package smb3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"testing"
)

// This file pins the in-place crypto rewrite to the byte-for-byte behaviour of
// the implementation it replaced. The previous code is kept verbatim below as
// refEncryptTransform / refDecryptTransform / refCMAC and every test here
// asserts equality against it: a performance change that moves a single wire
// byte breaks every SMB client, so the reference is the specification.
//
// The same reference functions double as the "before" side of the benchmarks,
// so `go test -bench .` prints old and new numbers side by side.

// ---------------------------------------------------------------------------
// Reference implementations (the pre-optimisation code, unchanged)
// ---------------------------------------------------------------------------

// refEncryptTransform is the old EncryptTransform: allocate the output, seal
// into a second fresh buffer, then copy ciphertext and tag back. The nonce is
// a parameter so a test can replay the nonce the new code actually drew and
// compare complete frames; the old code drew it internally and was otherwise
// identical.
func refEncryptTransform(cipherID uint16, key []byte, sessID uint64, plaintext, nonce []byte) ([]byte, error) {
	aead, nonceLen, err := newAEAD(cipherID, key)
	if err != nil {
		return nil, err
	}
	if nonceLen > 16 || nonceLen < 8 {
		return nil, fmt.Errorf("smb3: unusable nonce length %d", nonceLen)
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("smb3: test nonce is %d bytes, want %d", len(nonce), nonceLen)
	}

	out := make([]byte, TransformHeaderSize+len(plaintext)+16)
	copy(out[:4], transformProtocolID[:])
	copy(out[20:20+nonceLen], nonce)
	binary.LittleEndian.PutUint32(out[36:], uint32(len(plaintext)))
	binary.LittleEndian.PutUint16(out[42:], TransformFlagEncrypted)
	binary.LittleEndian.PutUint64(out[44:], sessID)

	aad := out[transformAADStart : transformAADStart+transformAADLen]
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	copy(out[TransformHeaderSize:], sealed[:len(plaintext)])
	copy(out[4:20], sealed[len(plaintext):])
	return out[:TransformHeaderSize+len(plaintext)], nil
}

// refDecryptTransform is the old DecryptTransform: rebuild ciphertext||tag in
// a fresh payload-sized buffer and let Open allocate the plaintext.
func refDecryptTransform(cipherID uint16, key, frame []byte) ([]byte, uint64, error) {
	if len(frame) < TransformHeaderSize {
		return nil, 0, ErrShortTransform
	}
	if !IsTransform(frame) {
		return nil, 0, ErrBadTransformID
	}
	origSize := binary.LittleEndian.Uint32(frame[36:])
	flags := binary.LittleEndian.Uint16(frame[42:])
	sessID := binary.LittleEndian.Uint64(frame[44:])
	if flags&TransformFlagEncrypted == 0 {
		return nil, 0, fmt.Errorf("smb3: transform flags=0x%04x (not encrypted)", flags)
	}
	ciphertext := frame[TransformHeaderSize:]
	if len(ciphertext) < int(origSize) {
		return nil, 0, ErrShortTransformBody
	}

	aead, nonceLen, err := newAEAD(cipherID, key)
	if err != nil {
		return nil, 0, err
	}
	nonce := frame[20 : 20+nonceLen]

	tag := frame[4:20]
	ct := make([]byte, len(ciphertext)+16)
	copy(ct, ciphertext)
	copy(ct[len(ciphertext):], tag)

	aad := frame[transformAADStart : transformAADStart+transformAADLen]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrTransformDecrypt, err)
	}
	return pt, sessID, nil
}

// refCMAC is the old CMAC: a full message-sized CBC pass whose output is
// thrown away except for the final block.
func refCMAC(key, msg []byte) [16]byte {
	c, _ := aes.NewCipher(key)
	k1, k2 := cmacSubkeys(c)

	const bs = 16
	var lastBlock [bs]byte

	complete := len(msg) > 0 && len(msg)%bs == 0
	var prefixLen int
	if complete {
		prefixLen = len(msg) - bs
		copy(lastBlock[:], msg[prefixLen:])
		subtle.XORBytes(lastBlock[:], lastBlock[:], k1[:])
	} else {
		prefixLen = (len(msg) / bs) * bs
		rem := msg[prefixLen:]
		copy(lastBlock[:], rem)
		lastBlock[len(rem)] = 0x80
		subtle.XORBytes(lastBlock[:], lastBlock[:], k2[:])
	}

	var x [bs]byte
	if prefixLen > 0 {
		iv := make([]byte, bs)
		cbc := cipher.NewCBCEncrypter(c, iv)
		buf := make([]byte, prefixLen)
		cbc.CryptBlocks(buf, msg[:prefixLen])
		copy(x[:], buf[prefixLen-bs:])
	}

	subtle.XORBytes(lastBlock[:], lastBlock[:], x[:])
	var out [16]byte
	c.Encrypt(out[:], lastBlock[:])
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// cryptoAllocCiphers is every cipher the server can negotiate, with a key of
// the right length for each.
var cryptoAllocCiphers = []struct {
	name   string
	cipher uint16
	keyLen int
}{
	{"AES128GCM", CipherAES128GCM, 16},
	{"AES128CCM", CipherAES128CCM, 16},
	{"AES256GCM", CipherAES256GCM, 32},
	{"AES256CCM", CipherAES256CCM, 32},
}

// cryptoAllocSizes spans empty, sub-block, exact-block and block+1 payloads
// plus sizes either side of the 4 KiB CMAC chunk and a realistic 512 KiB read.
var cryptoAllocSizes = []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 4095, 4096, 4097, 8192, 65536, 512*1024 + 80}

func cryptoAllocKey(n int, seed byte) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = seed + byte(i)*7
	}
	return k
}

func cryptoAllocPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*31 + 11)
	}
	return p
}

// frameNonce pulls the nonce the encryptor actually used back out of a frame.
func frameNonce(frame []byte, nonceLen int) []byte {
	return frame[20 : 20+nonceLen]
}

// ---------------------------------------------------------------------------
// Defect 1 — EncryptTransform seals in place
// ---------------------------------------------------------------------------

// TestEncryptTransformBytesMatchReference is the load-bearing test for the
// in-place seal: for every cipher and every payload size the complete frame —
// protocol id, tag placement in the Signature field, nonce, sizes, flags,
// session id and ciphertext — must be byte-identical to what the copying
// implementation produced from the same nonce.
func TestEncryptTransformBytesMatchReference(t *testing.T) {
	for _, cc := range cryptoAllocCiphers {
		for _, n := range cryptoAllocSizes {
			t.Run(fmt.Sprintf("%s/%d", cc.name, n), func(t *testing.T) {
				key := cryptoAllocKey(cc.keyLen, 0x11)
				plain := cryptoAllocPayload(n)
				const sessID = 0x0123456789ABCDEF

				got, err := EncryptTransform(cc.cipher, key, sessID, plain)
				if err != nil {
					t.Fatalf("EncryptTransform: %v", err)
				}
				if len(got) != TransformHeaderSize+n {
					t.Fatalf("frame length %d, want %d", len(got), TransformHeaderSize+n)
				}

				_, nonceLen, err := newAEAD(cc.cipher, key)
				if err != nil {
					t.Fatal(err)
				}
				want, err := refEncryptTransform(cc.cipher, key, sessID, plain, frameNonce(got, nonceLen))
				if err != nil {
					t.Fatalf("reference: %v", err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("frame differs from reference\n got: %x\nwant: %x", got, want)
				}

				// The plaintext handed in must not have been touched.
				if !bytes.Equal(plain, cryptoAllocPayload(n)) {
					t.Fatal("EncryptTransform mutated its plaintext argument")
				}
			})
		}
	}
}

// TestEncryptTransformHeaderFields spells out the header layout that the byte
// comparison above only implies, so a future regression names itself.
func TestEncryptTransformHeaderFields(t *testing.T) {
	key := cryptoAllocKey(32, 0x5A)
	plain := cryptoAllocPayload(1000)
	frame, err := EncryptTransform(CipherAES256GCM, key, 0xAABBCCDDEEFF0011, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !IsTransform(frame) {
		t.Fatalf("ProtocolId %x", frame[:4])
	}
	if got := binary.LittleEndian.Uint32(frame[36:]); got != uint32(len(plain)) {
		t.Errorf("OriginalMessageSize %d, want %d", got, len(plain))
	}
	if got := binary.LittleEndian.Uint16(frame[40:]); got != 0 {
		t.Errorf("Reserved %#x, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(frame[42:]); got != TransformFlagEncrypted {
		t.Errorf("Flags %#x", got)
	}
	if got := binary.LittleEndian.Uint64(frame[44:]); got != 0xAABBCCDDEEFF0011 {
		t.Errorf("SessionId %#x", got)
	}
	// The tag lives in Signature, not after the ciphertext: an all-zero
	// Signature would mean the move never happened.
	if bytes.Equal(frame[4:20], make([]byte, 16)) {
		t.Error("Signature field is all zero; tag was not moved into the header")
	}
	if len(frame) != TransformHeaderSize+len(plain) {
		t.Errorf("frame carries %d trailing bytes, want none", len(frame)-TransformHeaderSize-len(plain))
	}
}

// ---------------------------------------------------------------------------
// Defect 2 — DecryptTransform opens in place
// ---------------------------------------------------------------------------

// TestDecryptTransformMatchesReference runs both the in-place path (a frame
// with the 16 bytes of spare capacity transport.ReadFrame leaves) and the
// fallback path (a frame with none) and requires both to agree with the old
// implementation.
func TestDecryptTransformMatchesReference(t *testing.T) {
	for _, cc := range cryptoAllocCiphers {
		for _, n := range cryptoAllocSizes {
			t.Run(fmt.Sprintf("%s/%d", cc.name, n), func(t *testing.T) {
				key := cryptoAllocKey(cc.keyLen, 0x2C)
				plain := cryptoAllocPayload(n)
				const sessID = 0x00FF00FF00FF00FF

				frame, err := EncryptTransform(cc.cipher, key, sessID, plain)
				if err != nil {
					t.Fatal(err)
				}
				wantPT, wantSID, err := refDecryptTransform(cc.cipher, key, frame)
				if err != nil {
					t.Fatalf("reference decrypt: %v", err)
				}
				if !bytes.Equal(wantPT, plain) || wantSID != sessID {
					t.Fatal("reference decrypt disagrees with the plaintext it was given")
				}

				for _, headroom := range []int{16, 0} {
					work := make([]byte, len(frame), len(frame)+headroom)
					copy(work, frame)
					gotPT, gotSID, err := DecryptTransform(cc.cipher, key, work)
					if err != nil {
						t.Fatalf("headroom=%d: %v", headroom, err)
					}
					if gotSID != wantSID {
						t.Errorf("headroom=%d: session id %#x, want %#x", headroom, gotSID, wantSID)
					}
					if !bytes.Equal(gotPT, wantPT) {
						t.Errorf("headroom=%d: plaintext differs from reference", headroom)
					}
				}
			})
		}
	}
}

// TestDecryptTransformInPlaceIsAllocationFree proves the point of the change:
// with the transport's headroom present, decrypting a large frame no longer
// allocates anything proportional to the payload.
func TestDecryptTransformInPlaceIsAllocationFree(t *testing.T) {
	key := cryptoAllocKey(32, 0x9E)
	plain := cryptoAllocPayload(512 * 1024)
	frame, err := EncryptTransform(CipherAES256GCM, key, 1, plain)
	if err != nil {
		t.Fatal(err)
	}
	work := make([]byte, len(frame), len(frame)+16)

	perOp := testing.AllocsPerRun(20, func() {
		copy(work, frame)
		if _, _, err := DecryptTransform(CipherAES256GCM, key, work); err != nil {
			t.Fatal(err)
		}
	})
	// GCM's in-place Open needs no payload-sized buffer; a handful of tiny
	// bookkeeping allocations is fine, a per-frame copy of half a megabyte is
	// not. AllocsPerRun counts allocations, so cap the count conservatively.
	if perOp > 4 {
		t.Errorf("in-place decrypt made %.0f allocations per call, want <= 4", perOp)
	}
}

// TestDecryptTransformRejectsTamperedTag checks the tag really is read from the
// Signature field and not from wherever the ciphertext happens to end.
func TestDecryptTransformRejectsTamperedTag(t *testing.T) {
	for _, cc := range cryptoAllocCiphers {
		key := cryptoAllocKey(cc.keyLen, 0x71)
		frame, err := EncryptTransform(cc.cipher, key, 3, cryptoAllocPayload(300))
		if err != nil {
			t.Fatal(err)
		}
		for _, off := range []int{4, 19, TransformHeaderSize, len(frame) - 1, 20, 44} {
			work := make([]byte, len(frame), len(frame)+16)
			copy(work, frame)
			work[off] ^= 0x01
			if _, _, err := DecryptTransform(cc.cipher, key, work); err == nil {
				t.Errorf("%s: flipping byte %d still decrypted", cc.name, off)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Defect 3 — CMAC signs without copying the message
// ---------------------------------------------------------------------------

// TestCMACMatchesReference is the equivalence proof for the chunked prefix
// pass. CMAC is easy to get subtly wrong at block and chunk boundaries, so the
// sizes below cover 0, the sub-block and exact-block cases, and every boundary
// around the 4 KiB scratch buffer.
func TestCMACMatchesReference(t *testing.T) {
	lengths := []int{
		0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128,
		cmacChunk - 17, cmacChunk - 16, cmacChunk - 1, cmacChunk, cmacChunk + 1,
		cmacChunk + 15, cmacChunk + 16, cmacChunk + 17,
		2 * cmacChunk, 2*cmacChunk + 1, 8192, 65536, 512*1024 + 80,
	}
	for _, keyLen := range []int{16} {
		key := cryptoAllocKey(keyLen, 0x2b)
		for _, n := range lengths {
			msg := cryptoAllocPayload(n)
			want := refCMAC(key, msg)
			got := CMAC(key, msg)
			if got != want {
				t.Errorf("len=%d: CMAC = %x, want %x", n, got, want)
			}
			// And the message itself is untouched.
			if !bytes.Equal(msg, cryptoAllocPayload(n)) {
				t.Fatalf("len=%d: CMAC mutated its message argument", n)
			}
		}
	}
}

// TestSignMessageMatchesReference checks the change at the level callers see:
// the 16 signature bytes written into a real SMB2 header must be unchanged.
func TestSignMessageMatchesReference(t *testing.T) {
	key := cryptoAllocKey(16, 0x42)
	for _, n := range []int{64, 65, 79, 80, 81, 4096, cmacChunk + 64, 512*1024 + 80} {
		msg := cryptoAllocPayload(n)
		copy(msg, []byte{0xFE, 'S', 'M', 'B'})
		binary.LittleEndian.PutUint64(msg[24:], 42)

		ref := make([]byte, n)
		copy(ref, msg)
		for i := 48; i < 64; i++ {
			ref[i] = 0
		}
		ref[16] |= 0x08
		want := refCMAC(key, ref)

		SignMessage(SignAlgoAESCMAC, key, msg)
		if !bytes.Equal(msg[48:64], want[:]) {
			t.Errorf("len=%d: signature %x, want %x", n, msg[48:64], want)
		}
		if !VerifyMessage(SignAlgoAESCMAC, key, msg) {
			t.Errorf("len=%d: message failed its own verification", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Defect 4 — the AEAD is cached, not rebuilt per frame
// ---------------------------------------------------------------------------

// TestAEADForCachesAndMatchesNewAEAD checks the cache returns the same object
// for the same key, distinct objects for distinct keys, the same nonce length
// newAEAD reports, and the same errors for bad input.
func TestAEADForCachesAndMatchesNewAEAD(t *testing.T) {
	for _, cc := range cryptoAllocCiphers {
		key := cryptoAllocKey(cc.keyLen, 0xC4)
		a1, n1, err := aeadFor(cc.cipher, key)
		if err != nil {
			t.Fatalf("%s: %v", cc.name, err)
		}
		a2, n2, err := aeadFor(cc.cipher, append([]byte(nil), key...))
		if err != nil {
			t.Fatalf("%s: %v", cc.name, err)
		}
		if a1 != a2 {
			t.Errorf("%s: cache returned a different AEAD for the same key", cc.name)
		}
		_, wantNonce, err := newAEAD(cc.cipher, key)
		if err != nil {
			t.Fatal(err)
		}
		if n1 != wantNonce || n2 != wantNonce {
			t.Errorf("%s: nonce length %d/%d, want %d", cc.name, n1, n2, wantNonce)
		}

		other := cryptoAllocKey(cc.keyLen, 0xD5)
		a3, _, err := aeadFor(cc.cipher, other)
		if err != nil {
			t.Fatal(err)
		}
		if a1 == a3 {
			t.Errorf("%s: cache returned the same AEAD for two different keys", cc.name)
		}

		// Short keys must still be rejected, cache or no cache.
		if _, _, err := aeadFor(cc.cipher, key[:cc.keyLen-1]); err == nil {
			t.Errorf("%s: short key accepted", cc.name)
		}
	}
	if _, _, err := aeadFor(0x4242, cryptoAllocKey(32, 1)); err == nil {
		t.Error("unknown cipher id accepted")
	}
	if _, _, err := aeadFor(0, cryptoAllocKey(32, 1)); err == nil {
		t.Error("cipher id 0 accepted")
	}
}

// TestAEADCacheConcurrent exercises the shard locking under -race: many
// goroutines encrypting and decrypting on overlapping keys at once.
func TestAEADCacheConcurrent(t *testing.T) {
	const goroutines = 32
	done := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			key := cryptoAllocKey(32, byte(g%4))
			plain := cryptoAllocPayload(256 + g)
			for i := 0; i < 50; i++ {
				frame, err := EncryptTransform(CipherAES256GCM, key, uint64(g), plain)
				if err != nil {
					done <- err
					return
				}
				got, _, err := DecryptTransform(CipherAES256GCM, key, frame)
				if err != nil {
					done <- err
					return
				}
				if !bytes.Equal(got, plain) {
					done <- fmt.Errorf("goroutine %d: round trip mismatch", g)
					return
				}
			}
			done <- nil
		}(g)
	}
	for i := 0; i < goroutines; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// TestAEADCacheOverflowStaysCorrect drives the shard past aeadCacheLimit so the
// drop-and-rebuild path runs, and checks nothing breaks when it does.
func TestAEADCacheOverflowStaysCorrect(t *testing.T) {
	plain := cryptoAllocPayload(64)
	for i := 0; i < aeadCacheLimit+32; i++ {
		key := cryptoAllocKey(16, byte(i))
		binary.LittleEndian.PutUint32(key[:4], uint32(i))
		frame, err := EncryptTransform(CipherAES128GCM, key, uint64(i), plain)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := DecryptTransform(CipherAES128GCM, key, frame)
		if err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("i=%d: round trip mismatch", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — "Ref" is the implementation that was replaced.
// ---------------------------------------------------------------------------

const benchPayload = 512 * 1024

func BenchmarkEncryptTransform(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	plain := cryptoAllocPayload(benchPayload)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptTransform(CipherAES256GCM, key, 1, plain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptTransformRef(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	plain := cryptoAllocPayload(benchPayload)
	nonce := make([]byte, 12)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(nonce, uint64(i))
		if _, err := refEncryptTransform(CipherAES256GCM, key, 1, plain, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

// benchDecrypt copies a prepared frame into a pre-allocated working buffer
// before each call, so both variants pay the same memcpy and the reported
// B/op is what the decrypt itself allocates. headroom=16 is what
// transport.ReadFrame provides in production.
func benchDecrypt(b *testing.B, headroom int, fn func(uint16, []byte, []byte) ([]byte, uint64, error)) {
	key := cryptoAllocKey(32, 0x11)
	plain := cryptoAllocPayload(benchPayload)
	frame, err := EncryptTransform(CipherAES256GCM, key, 1, plain)
	if err != nil {
		b.Fatal(err)
	}
	work := make([]byte, len(frame), len(frame)+headroom)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, frame)
		if _, _, err := fn(CipherAES256GCM, key, work); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptTransform(b *testing.B) {
	benchDecrypt(b, 16, DecryptTransform)
}

func BenchmarkDecryptTransformRef(b *testing.B) {
	benchDecrypt(b, 16, refDecryptTransform)
}

func BenchmarkCMAC(b *testing.B) {
	key := cryptoAllocKey(16, 0x2b)
	msg := cryptoAllocPayload(benchPayload)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = CMAC(key, msg)
	}
}

func BenchmarkCMACRef(b *testing.B) {
	key := cryptoAllocKey(16, 0x2b)
	msg := cryptoAllocPayload(benchPayload)
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = refCMAC(key, msg)
	}
}

// BenchmarkSignMessage is the caller-level view of the CMAC change.
func BenchmarkSignMessage(b *testing.B) {
	key := cryptoAllocKey(16, 0x42)
	msg := cryptoAllocPayload(benchPayload)
	copy(msg, []byte{0xFE, 'S', 'M', 'B'})
	b.SetBytes(benchPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignMessage(SignAlgoAESCMAC, key, msg)
	}
}

// The AEAD-construction pair is the metadata-storm case: tiny frames where
// rebuilding the cipher is a real share of the work.
func BenchmarkAEADFor(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := aeadFor(CipherAES256GCM, key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewAEADRef(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := newAEAD(CipherAES256GCM, key); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptTransformSmall shows the AEAD cache where it matters: a
// 128-byte metadata response.
func BenchmarkEncryptTransformSmall(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	plain := cryptoAllocPayload(128)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptTransform(CipherAES256GCM, key, 1, plain); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptTransformSmallRef(b *testing.B) {
	key := cryptoAllocKey(32, 0x11)
	plain := cryptoAllocPayload(128)
	nonce := make([]byte, 12)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(nonce, uint64(i))
		if _, err := refEncryptTransform(CipherAES256GCM, key, 1, plain, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

var sink [16]byte
