package smb3

import (
	"crypto/cipher"
	"sync"
)

// Constructing a cipher.AEAD is not free: aes.NewCipher expands the key
// schedule and cipher.NewGCM precomputes the GHASH product table, which
// together cost ~243 ns and 1280 B on every call. Doing that per frame is
// invisible next to a 512 KiB read but it is pure overhead during a metadata
// storm, where a client fires thousands of tiny encrypted requests a second
// and the AEAD setup is a measurable share of each one.
//
// A cipher.AEAD is safe for concurrent use once built, so one instance per
// (cipher id, key) can be shared by every connection. The natural home for it
// would be the Session that owns the key, but Session lives in internal/parent;
// keeping the cache here means smb3 stays self-contained and every caller —
// present and future — benefits without changing a signature. If the AEAD is
// later hung off the session, this cache becomes dead weight and should go.
//
// Concurrency: each cipher id gets its own shard with its own RWMutex, so the
// hot path is a read-locked map lookup. The map is keyed by the raw key bytes;
// `m[string(rawKey)]` is the form the compiler rewrites into an allocation-free
// lookup, which is why the key type is string and not a struct.
type cachedAEAD struct {
	aead     cipher.AEAD
	nonceLen int
}

// aeadCacheLimit bounds a shard so that a long-lived process churning through
// sessions cannot grow the cache without limit (and cannot pin unbounded key
// material in memory). Sessions are far fewer than this in practice; on
// overflow the shard is dropped wholesale rather than evicted one entry at a
// time, which costs one rebuild per live key and needs no bookkeeping.
const aeadCacheLimit = 512

type aeadCacheShard struct {
	mu sync.RWMutex
	m  map[string]cachedAEAD
}

// One shard per cipher id. Ids run 0x0001..0x0004 (CipherAES256GCM is the
// largest), and index 0 is never used because cipher id 0 means "encryption
// not negotiated".
var aeadCaches [CipherAES256GCM + 1]aeadCacheShard

// aeadFor returns a cached cipher.AEAD for (cipherID, rawKey), building and
// caching one on first use. It is the allocation-free equivalent of newAEAD
// and returns the same values, including the same errors.
func aeadFor(cipherID uint16, rawKey []byte) (cipher.AEAD, int, error) {
	if cipherID == 0 || int(cipherID) >= len(aeadCaches) {
		// Unknown cipher: let newAEAD produce the error.
		return newAEAD(cipherID, rawKey)
	}
	sh := &aeadCaches[cipherID]

	sh.mu.RLock()
	e, ok := sh.m[string(rawKey)]
	sh.mu.RUnlock()
	if ok {
		return e.aead, e.nonceLen, nil
	}

	a, nonceLen, err := newAEAD(cipherID, rawKey)
	if err != nil {
		return nil, 0, err
	}

	sh.mu.Lock()
	if sh.m == nil || len(sh.m) >= aeadCacheLimit {
		sh.m = make(map[string]cachedAEAD, 16)
	}
	sh.m[string(rawKey)] = cachedAEAD{aead: a, nonceLen: nonceLen}
	sh.mu.Unlock()

	// Two goroutines racing on the same new key each build an AEAD and one
	// wins the map; both are equivalent, so the loser is simply dropped.
	return a, nonceLen, nil
}
