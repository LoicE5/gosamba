package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// --- fixture ---

// newChainDispatcher builds a Dispatcher wired the way ServeConn wires one —
// a registered, authenticated session and a session table — so Dispatch can be
// driven message by message the way the connection's chain loop drives it.
func newChainDispatcher(t testing.TB, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir}
	tbl := NewSessionTable()
	sess := tbl.New()
	sess.Authenticated = true
	tree := sess.AddTree(share)
	d := &Dispatcher{
		Conn:     &Connection{MaxIOSize: 1 << 20},
		Sessions: tbl,
		Shares:   []config.ShareConfig{share},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		locks:    sharedLockManager,
		async:    &asyncTable{},
	}
	return d, sess, tree
}

// compoundMember is one decoded member of a compounded response frame.
type compoundMember struct {
	hdr  smb2.Header
	msg  []byte // the member's bytes, exactly NextCommand long (padding included)
	body []byte
}

// splitCompound walks a single NBSS frame's SMB2 chain the way a client does,
// asserting the framing invariants of MS-SMB2 §3.3.4.1 along the way: every
// member but the last announces its own padded length in NextCommand, that
// length is 8-byte aligned, and the last member announces 0 and runs exactly to
// the end of the frame.
func splitCompound(t *testing.T, frame []byte) []compoundMember {
	t.Helper()
	if len(frame) < transport.FrameHeaderSize {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if frame[0] != 0x00 {
		t.Fatalf("NBSS type byte = 0x%02x, want 0x00", frame[0])
	}
	declared := int(frame[1])<<16 | int(frame[2])<<8 | int(frame[3])
	payload := frame[transport.FrameHeaderSize:]
	if declared != len(payload) {
		t.Fatalf("NBSS length %d does not match payload %d", declared, len(payload))
	}

	var out []compoundMember
	off := 0
	for {
		if len(payload)-off < smb2.HeaderSize {
			t.Fatalf("member %d: only %d bytes left, need a %d-byte header",
				len(out), len(payload)-off, smb2.HeaderSize)
		}
		hdr, err := smb2.DecodeHeader(payload[off : off+smb2.HeaderSize])
		if err != nil {
			t.Fatalf("member %d: decode header: %v", len(out), err)
		}
		end := len(payload)
		if hdr.NextCommand != 0 {
			if hdr.NextCommand%8 != 0 {
				t.Errorf("member %d: NextCommand %d is not 8-byte aligned",
					len(out), hdr.NextCommand)
			}
			end = off + int(hdr.NextCommand)
			if end > len(payload) {
				t.Fatalf("member %d: NextCommand %d overruns the %d-byte frame",
					len(out), hdr.NextCommand, len(payload))
			}
		}
		out = append(out, compoundMember{
			hdr:  hdr,
			msg:  payload[off:end],
			body: payload[off+smb2.HeaderSize : end],
		})
		if hdr.NextCommand == 0 {
			if end != len(payload) {
				t.Errorf("last member ends at %d, frame is %d bytes", end, len(payload))
			}
			return out
		}
		off = end
	}
}

// --- request-body builders for the chains the macOS client actually sends ---

func buildQueryInfoBody(fileID [16]byte, infoType, infoClass uint8, outLen uint32) []byte {
	body := make([]byte, 40)
	binary.LittleEndian.PutUint16(body[0:], 41) // StructureSize
	body[2] = infoType
	body[3] = infoClass
	binary.LittleEndian.PutUint32(body[4:], outLen)
	copy(body[24:40], fileID[:])
	return body
}

func buildSetInfoEOFBody(fileID [16]byte, size uint64) []byte {
	const headerSize = 64
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, size)
	body := make([]byte, 32)
	binary.LittleEndian.PutUint16(body[0:], 33) // StructureSize
	body[2] = smb2.InfoTypeFile
	body[3] = smb2.FileEndOfFileInformation
	binary.LittleEndian.PutUint32(body[4:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(body[8:], uint16(headerSize+32)) // BufferOffset
	copy(body[16:32], fileID[:])
	return append(body, buf...)
}

// runChain dispatches every message of one inbound frame on a per-frame
// dispatcher and returns the single frame its responses were flushed into.
func runChain(t *testing.T, d *Dispatcher, sess *Session, encrypted bool, msgs []struct {
	hdr  smb2.Header
	body []byte
}) []byte {
	t.Helper()
	fd := d.forFrame(encrypted)
	var buf bytes.Buffer
	for i := range msgs {
		msgs[i].hdr.SessionID = sess.ID
		if !fd.Dispatch(&buf, msgs[i].hdr, msgs[i].body, nil) {
			t.Fatalf("message %d dropped the connection", i)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("chain wrote %d bytes before it was flushed", buf.Len())
	}
	fd.flush(&buf)
	return buf.Bytes()
}

type chainMsg = struct {
	hdr  smb2.Header
	body []byte
}

// TestCompound_CreateQueryInfo proves a CREATE + QUERY_INFO chain — the pair
// Finder opens every file with — comes back as ONE frame whose members are
// linked and individually decodable.
//
// Before this the two responses went out as two frames, which is what the macOS
// client latches SMBV_NON_COMPOUND_REPLIES on: "Once set, this remains set
// forever" (SMBClient, smb_iod.c).
func TestCompound_CreateQueryInfo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newChainDispatcher(t, dir)

	frame := runChain(t, d, sess, false, []chainMsg{
		{
			hdr:  smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			body: buildCreateBody("doc.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandQueryInfo, TreeID: tree.ID,
				MessageID: 1, Flags: smb2.FlagRelatedOps},
			body: buildQueryInfoBody(previousHandleFileID, smb2.InfoTypeFile,
				smb2.FileAllInformation, 4096),
		},
	})

	members := splitCompound(t, frame)
	if len(members) != 2 {
		t.Fatalf("got %d members in the reply frame, want 2 (one compounded frame)", len(members))
	}
	if members[0].hdr.Command != smb2.CommandCreate {
		t.Errorf("member 0 command = %v, want CREATE", members[0].hdr.Command)
	}
	if members[1].hdr.Command != smb2.CommandQueryInfo {
		t.Errorf("member 1 command = %v, want QUERY_INFO", members[1].hdr.Command)
	}
	for i, m := range members {
		if smb2.Status(m.hdr.Status) != smb2.StatusSuccess {
			t.Errorf("member %d status = 0x%08X, want SUCCESS", i, m.hdr.Status)
		}
	}
	if members[1].hdr.MessageID != 1 {
		t.Errorf("member 1 MessageId = %d, want 1", members[1].hdr.MessageID)
	}
	// Each member is independently decodable: the CREATE response announces
	// StructureSize 89 and the QUERY_INFO response StructureSize 9.
	if got := binary.LittleEndian.Uint16(members[0].body); got != 89 {
		t.Errorf("member 0 StructureSize = %d, want 89 (CREATE response)", got)
	}
	if got := binary.LittleEndian.Uint16(members[1].body); got != 9 {
		t.Errorf("member 1 StructureSize = %d, want 9 (QUERY_INFO response)", got)
	}
}

// TestCompound_CreateWriteSetInfoCloseLinks pins the framing arithmetic on the
// four-member chain a client uses to create-and-write a small file: every
// member but the last carries its own padded length in NextCommand, and the
// last carries 0.
func TestCompound_CreateWriteSetInfoCloseLinks(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newChainDispatcher(t, dir)

	data := []byte("chain-written payload")
	frame := runChain(t, d, sess, false, []chainMsg{
		{
			hdr: smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			body: buildCreateBody("new.txt", smb2.CreateDispositionCreate, 0,
				smb2.AccessGenericRead|smb2.AccessGenericWrite, nil),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandWrite, TreeID: tree.ID,
				MessageID: 1, Flags: smb2.FlagRelatedOps},
			body: buildWriteBody(previousHandleFileID, 0, data),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandSetInfo, TreeID: tree.ID,
				MessageID: 2, Flags: smb2.FlagRelatedOps},
			body: buildSetInfoEOFBody(previousHandleFileID, uint64(len(data))),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandClose, TreeID: tree.ID,
				MessageID: 3, Flags: smb2.FlagRelatedOps},
			body: buildCloseBody(previousHandleFileID),
		},
	})

	members := splitCompound(t, frame)
	if len(members) != 4 {
		t.Fatalf("got %d members, want 4 in one frame", len(members))
	}
	wantCmds := []smb2.Command{
		smb2.CommandCreate, smb2.CommandWrite, smb2.CommandSetInfo, smb2.CommandClose,
	}
	for i, want := range wantCmds {
		if members[i].hdr.Command != want {
			t.Errorf("member %d command = %v, want %v", i, members[i].hdr.Command, want)
		}
		if smb2.Status(members[i].hdr.Status) != smb2.StatusSuccess {
			t.Errorf("member %d status = 0x%08X, want SUCCESS", i, members[i].hdr.Status)
		}
	}
	// Every member but the last announces its own padded length.
	for i := 0; i < len(members)-1; i++ {
		if got, want := members[i].hdr.NextCommand, uint32(len(members[i].msg)); got != want {
			t.Errorf("member %d NextCommand = %d, want %d (its own padded length)", i, got, want)
		}
	}
	if last := members[len(members)-1]; last.hdr.NextCommand != 0 {
		t.Errorf("last member NextCommand = %d, want 0", last.hdr.NextCommand)
	}

	// And the chain really did the work.
	got, err := os.ReadFile(filepath.Join(dir, "new.txt"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("file contents %q, want %q", got, data)
	}
}

// TestCompound_SignedMembersVerifyIndividually proves signing is applied per
// member inside the compounded frame, over exactly the NextCommand bytes the
// member announces — padding included.
//
// That length is not a matter of taste: the macOS client hashes exactly that
// region ("if (nextCmdOffset != 0) reply_len = nextCmdOffset", SMBClient
// smb_crypt.c smb3_verify), and hashes to the end of the frame for the final
// member, whose NextCommand is 0.
func TestCompound_SignedMembersVerifyIndividually(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newChainDispatcher(t, dir)
	sess.SigningKey = bytes.Repeat([]byte{0x5A}, 16)
	d.Conn.Selection.SigningAlgo = smb2.SigningAlgo(smb3.SignAlgoAESCMAC)

	frame := runChain(t, d, sess, false, []chainMsg{
		{
			hdr:  smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			body: buildCreateBody("doc.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandQueryInfo, TreeID: tree.ID,
				MessageID: 1, Flags: smb2.FlagRelatedOps},
			body: buildQueryInfoBody(previousHandleFileID, smb2.InfoTypeFile,
				smb2.FileAllInformation, 4096),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandClose, TreeID: tree.ID,
				MessageID: 2, Flags: smb2.FlagRelatedOps},
			body: buildCloseBody(previousHandleFileID),
		},
	})

	members := splitCompound(t, frame)
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
	for i, m := range members {
		if m.hdr.Flags&smb2.FlagSigned == 0 {
			t.Errorf("member %d is not marked signed", i)
		}
		// VerifyMessage hashes the whole slice it is given, so handing it the
		// member's announced extent is the client's computation exactly.
		if !smb3.VerifyMessage(uint16(smb3.SignAlgoAESCMAC), sess.SigningKey, m.msg) {
			t.Errorf("member %d signature does not verify over its %d announced bytes",
				i, len(m.msg))
		}
	}
	// A signature computed over the unpadded message must NOT verify for a
	// padded member, which is what makes the length above load-bearing.
	if members[0].hdr.NextCommand%8 == 0 && len(members[0].msg) > smb2.HeaderSize {
		short := members[0].msg[:len(members[0].msg)-1]
		if smb3.VerifyMessage(uint16(smb3.SignAlgoAESCMAC), sess.SigningKey, short) {
			t.Errorf("member 0 also verifies over a truncated extent; the test proves nothing")
		}
	}
}

// TestCompound_EncryptedChainIsOneTransform proves an encrypted compound chain
// is wrapped in a single transform header covering the whole compounded frame,
// not one transform header per member (MS-SMB2 §3.3.4.1.4).
func TestCompound_EncryptedChainIsOneTransform(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, sess, tree := newChainDispatcher(t, dir)
	sess.S2CCipherKey = bytes.Repeat([]byte{0x31}, 16)
	sess.SigningKey = bytes.Repeat([]byte{0x5A}, 16)
	d.Conn.Selection.Cipher = smb2.Cipher(smb3.CipherAES128GCM)
	d.Conn.Selection.SigningAlgo = smb2.SigningAlgo(smb3.SignAlgoAESCMAC)

	frame := runChain(t, d, sess, true, []chainMsg{
		{
			hdr:  smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			body: buildCreateBody("doc.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandQueryInfo, TreeID: tree.ID,
				MessageID: 1, Flags: smb2.FlagRelatedOps},
			body: buildQueryInfoBody(previousHandleFileID, smb2.InfoTypeFile,
				smb2.FileAllInformation, 4096),
		},
	})

	payload := frame[transport.FrameHeaderSize:]
	if !smb3.IsTransform(payload) {
		t.Fatalf("encrypted chain did not come back inside a transform header")
	}
	plain, gotSess, err := smb3.DecryptTransform(uint16(smb3.CipherAES128GCM), sess.S2CCipherKey, payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotSess != sess.ID {
		t.Errorf("transform SessionId = %d, want %d", gotSess, sess.ID)
	}
	if smb3.IsTransform(plain) {
		t.Fatalf("the decrypted frame is itself a transform frame: members were wrapped individually")
	}

	// Re-frame the plaintext so the shared walker can check the member links.
	reframed := make([]byte, transport.FrameHeaderSize+len(plain))
	copy(reframed[transport.FrameHeaderSize:], plain)
	if err := transport.PutFrameHeader(reframed); err != nil {
		t.Fatal(err)
	}
	members := splitCompound(t, reframed)
	if len(members) != 2 {
		t.Fatalf("got %d members inside the single transform, want 2", len(members))
	}
	// Members under a transform header are not signed: the AEAD already
	// authenticates them (MS-SMB2 §3.3.4.1.4).
	for i, m := range members {
		if m.hdr.Flags&smb2.FlagSigned != 0 {
			t.Errorf("member %d is signed under a transform header", i)
		}
	}
}

// TestCompound_FailedFirstMemberStillInherits proves a related chain whose
// first member fails behaves as it did before compounding: the later members
// that name the previous handle inherit the failure (MS-SMB2 §3.3.5.2.7)
// rather than reporting something else, and all of it still comes back in one
// frame.
func TestCompound_FailedFirstMemberStillInherits(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newChainDispatcher(t, dir)

	frame := runChain(t, d, sess, false, []chainMsg{
		{
			// No such file, and no create disposition that would make one.
			hdr:  smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
			body: buildCreateBody("absent.txt", smb2.CreateDispositionOpen, 0, smb2.AccessGenericRead, nil),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandQueryInfo, TreeID: tree.ID,
				MessageID: 1, Flags: smb2.FlagRelatedOps},
			body: buildQueryInfoBody(previousHandleFileID, smb2.InfoTypeFile,
				smb2.FileAllInformation, 4096),
		},
		{
			hdr: smb2.Header{Command: smb2.CommandClose, TreeID: tree.ID,
				MessageID: 2, Flags: smb2.FlagRelatedOps},
			body: buildCloseBody(previousHandleFileID),
		},
	})

	members := splitCompound(t, frame)
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
	first := smb2.Status(members[0].hdr.Status)
	if first == smb2.StatusSuccess {
		t.Fatalf("CREATE of a missing file succeeded; the test proves nothing")
	}
	for i := 1; i < len(members); i++ {
		if got := smb2.Status(members[i].hdr.Status); got != first {
			t.Errorf("member %d status = 0x%08X, want the first member's 0x%08X",
				i, got, first)
		}
	}
}

// TestCompound_SingleResponseIsUnpadded proves the ordinary one-message frame
// is untouched: NextCommand 0, no padding, and no second copy of the buffer.
func TestCompound_SingleResponseIsUnpadded(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newChainDispatcher(t, dir)

	frame := runChain(t, d, sess, false, []chainMsg{{
		hdr:  smb2.Header{Command: smb2.CommandTreeConnect, TreeID: tree.ID},
		body: buildTreeConnectBody(`\\srv\share`),
	}})

	members := splitCompound(t, frame)
	if len(members) != 1 {
		t.Fatalf("got %d members, want 1", len(members))
	}
	if members[0].hdr.NextCommand != 0 {
		t.Errorf("lone response NextCommand = %d, want 0", members[0].hdr.NextCommand)
	}
}

// TestCompound_CancelProducesNoFrame proves a chain that answers nothing — an
// SMB2_CANCEL is completed by finishing the request it names, never with a
// response of its own — flushes nothing rather than an empty frame.
// --- a related CLOSE was short-circuited and its handle stranded ---
//
// macOS sends CREATE/SomeOp/CLOSE as one related chain (SMBClient
// kernel/netsmb/smb_iod.c: "The typical compound request would be
// Create/SomeOp/Close"). Dispatch refused any related op carrying the all-FF
// previous-handle sentinel once an earlier member had failed, which swallowed
// the CLOSE as well — leaving the descriptor, its byte-range locks and its
// share-mode reservation in place for the life of the connection. ksmbd
// resolves a sentinel CLOSE against the chain's stored FID and runs it whatever
// an earlier member did (fs/smb/server/smb2pdu.c, smb2_close).

// encodeChainMsg frames one member of a compound chain: a 64-byte SMB2 header
// carrying next as its NextCommand, followed by body.
func encodeChainMsg(t *testing.T, hdr smb2.Header, body []byte, next uint32) []byte {
	t.Helper()
	hdr.NextCommand = next
	h := make([]byte, smb2.HeaderSize)
	if err := smb2.EncodeHeader(h, hdr); err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	return append(h, body...)
}

// runRawChain walks a compound frame the way ServeConn's serveFrame does: one
// per-frame Dispatcher clone, then Dispatch per member over its own slice.
//
// This differs from runChain above in that it drives Dispatch from the raw,
// already-framed wire bytes (decoding each member's header off the frame)
// rather than from hdr/body struct pairs, so it exercises the same header
// decode path a real connection uses.
func runRawChain(t *testing.T, d *Dispatcher, frame []byte) {
	t.Helper()
	fd := d.forFrame(false)
	var sink bytes.Buffer
	defer fd.flush(&sink)
	for off := 0; off < len(frame); {
		hdr, err := smb2.DecodeHeader(frame[off : off+smb2.HeaderSize])
		if err != nil {
			t.Fatalf("DecodeHeader at %d: %v", off, err)
		}
		end := len(frame)
		if hdr.NextCommand != 0 {
			end = off + int(hdr.NextCommand)
		}
		msg := frame[off:end]
		if !fd.Dispatch(&sink, hdr, msg[smb2.HeaderSize:], msg) {
			return
		}
		if hdr.NextCommand == 0 {
			return
		}
		off = end
	}
}

// renameInfoBuf builds a FileRenameInformation SET_INFO buffer.
func renameInfoBuf(newName string, replace bool) []byte {
	nameU16 := utf16leName(newName)
	buf := make([]byte, 20+len(nameU16))
	if replace {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint32(buf[16:], uint32(len(nameU16)))
	copy(buf[20:], nameU16)
	return buf
}

// newRelatedChainDispatcher builds a Dispatcher that Dispatch can drive: it
// needs a SessionTable to resolve the SessionId, an authenticated session, a
// Connection, and the shared byte-range lock manager.
//
// This is deliberately a separate fixture from newChainDispatcher above (which
// this test cannot reuse without a name collision): it sets SessionID directly
// on each encoded header rather than having a shared runner stamp it in, since
// runRawChain drives Dispatch from raw wire bytes it decodes itself.
func newRelatedChainDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	share := config.ShareConfig{Name: "share", Path: shareDir}
	conn := &Connection{MaxIOSize: 1 << 20}
	conn.ClientGuid[0] = 0xC7
	d := &Dispatcher{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Shares:   []config.ShareConfig{share},
		Conn:     conn,
		Sessions: NewSessionTable(),
		locks:    sharedLockManager,
		async:    &asyncTable{},
	}
	sess := d.Sessions.New()
	sess.Authenticated = true
	tree := sess.AddTree(share)
	return d, sess, tree
}

func TestFixCompound_FailedMiddleOpStillClosesTheHandle(t *testing.T) {
	dir := t.TempDir()
	baseline := sharedShareModes.len()
	d, sess, tree := newRelatedChainDispatcher(t, dir)

	for _, n := range []string{"index.lock", "index"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// CREATE index.lock — succeeds.
	cb := buildCreateBodyShare("index.lock", smb2.CreateDispositionOpen, 0,
		smb2.AccessFileReadData|smb2.AccessFileWriteData|accDelete,
		shareAccessRead|shareAccessDelete, nil)
	createMsg := encodeChainMsg(t, smb2.Header{
		Command: smb2.CommandCreate, TreeID: tree.ID, SessionID: sess.ID, MessageID: 1,
	}, cb, uint32(smb2.HeaderSize+len(cb)))

	// SET_INFO rename onto an existing name without ReplaceIfExists — fails
	// with STATUS_OBJECT_NAME_COLLISION.
	sb := buildSetInfoBody(byte(smb2.InfoTypeFile), byte(smb2.FileRenameInformation),
		previousHandleFileID, renameInfoBuf("index", false))
	setMsg := encodeChainMsg(t, smb2.Header{
		Command: smb2.CommandSetInfo, TreeID: tree.ID, SessionID: sess.ID, MessageID: 2,
		Flags: smb2.FlagRelatedOps,
	}, sb, uint32(smb2.HeaderSize+len(sb)))

	// CLOSE on the sentinel — must run anyway.
	closeMsg := encodeChainMsg(t, smb2.Header{
		Command: smb2.CommandClose, TreeID: tree.ID, SessionID: sess.ID, MessageID: 3,
		Flags: smb2.FlagRelatedOps,
	}, buildCloseBody(previousHandleFileID), 0)

	runRawChain(t, d, append(append(createMsg, setMsg...), closeMsg...))

	if n := sess.OpenCount(); n != 0 {
		t.Errorf("session still holds %d open(s) after the chain's CLOSE, want 0", n)
	}
	if got := sharedShareModes.len(); got != baseline {
		t.Errorf("share-mode table holds %d reservations, want %d: the handle leaked its entry",
			got, baseline)
	}
}

func TestCompound_CancelProducesNoFrame(t *testing.T) {
	dir := t.TempDir()
	d, sess, _ := newChainDispatcher(t, dir)

	fd := d.forFrame(false)
	var buf bytes.Buffer
	cancelBody := make([]byte, 4)
	binary.LittleEndian.PutUint16(cancelBody, 4)
	if !fd.Dispatch(&buf, smb2.Header{Command: smb2.CommandCancel, SessionID: sess.ID, MessageID: 99}, cancelBody, nil) {
		t.Fatal("CANCEL dropped the connection")
	}
	fd.flush(&buf)
	if buf.Len() != 0 {
		t.Errorf("CANCEL produced %d bytes of response, want none", buf.Len())
	}
}
