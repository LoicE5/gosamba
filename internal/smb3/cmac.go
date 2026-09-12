package smb3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// cmacChunk is the size of the reusable scratch buffer the CMAC prefix pass
// writes its (discarded) ciphertext into. It must be a multiple of the AES
// block size. 4 KiB keeps the buffer L1-resident while still handing
// CryptBlocks enough work per call to stay on the AES-NI/ARM-AES fast path.
const cmacChunk = 4096

// CMAC computes AES-CMAC of msg with the given AES key (RFC 4493).
// The prefix (everything but the last block) is processed via
// crypto/cipher.NewCBCEncrypter, which uses Go's AES-NI/ARM-AES fast path,
// avoiding per-block interface dispatch overhead.
func CMAC(key, msg []byte) [16]byte {
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
		// CBC-encrypt the prefix; the final ciphertext block is the CBC-MAC
		// of the prefix and serves as the IV for the last block.
		//
		// Only that final block is wanted, so the prefix is run through a small
		// fixed scratch buffer rather than a message-sized one. A 512 KiB signed
		// write used to allocate — and immediately discard — a 512 KiB copy of
		// the message here; now it allocates cmacChunk bytes regardless of
		// message size (536 kB/op -> ~7.8 kB/op), and is slightly faster too
		// because the scratch stays in cache.
		//
		// Correctness rests on cipher.BlockMode carrying its chaining state
		// across CryptBlocks calls: encrypting the prefix in cmacChunk-sized
		// pieces is bit-identical to encrypting it in one call, provided every
		// piece except the last is a whole number of blocks (cmacChunk is a
		// multiple of bs and prefixLen always is too).
		iv := make([]byte, bs)
		cbc := cipher.NewCBCEncrypter(c, iv)
		var scratch [cmacChunk]byte
		for off := 0; off < prefixLen; off += cmacChunk {
			end := off + cmacChunk
			if end > prefixLen {
				end = prefixLen
			}
			cbc.CryptBlocks(scratch[:end-off], msg[off:end])
			copy(x[:], scratch[end-off-bs:end-off])
		}
	}

	subtle.XORBytes(lastBlock[:], lastBlock[:], x[:])
	var out [16]byte
	c.Encrypt(out[:], lastBlock[:])
	return out
}

func cmacSubkeys(c cipher.Block) (k1, k2 [16]byte) {
	const bs = 16
	var L [bs]byte
	c.Encrypt(L[:], L[:])
	k1 = leftShift(L)
	if L[0]&0x80 != 0 {
		k1[15] ^= 0x87
	}
	k2 = leftShift(k1)
	if k1[0]&0x80 != 0 {
		k2[15] ^= 0x87
	}
	return
}

func leftShift(in [16]byte) [16]byte {
	var out [16]byte
	overflow := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = (in[i] << 1) | overflow
		if in[i]&0x80 != 0 {
			overflow = 1
		} else {
			overflow = 0
		}
	}
	return out
}
