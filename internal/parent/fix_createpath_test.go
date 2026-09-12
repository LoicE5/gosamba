package parent

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/vfs"
)

// --- CREATE-path defects ---
//
// Four things went wrong between "the client sent a CREATE" and "the server
// answered it":
//
//   - an in-share symlink was unopenable. ResolveSecureNorm returns the link's
//     own path, the open is O_NOFOLLOW, and the resulting ELOOP was reported as
//     ACCESS_DENIED — while statusFromErr reported the very same ELOOP as
//     OBJECT_PATH_NOT_FOUND. Finder listed the link as an ordinary file (the
//     server does not claim FILE_SUPPORTS_REPARSE_POINTS, so macOS never asks
//     for the reparse point and believes the FILE_ATTRIBUTE_NORMAL answer) and
//     every open of it was refused;
//   - FILE_SUPERSEDE shared the FILE_OVERWRITE_IF arm and reported
//     FILE_WAS_OVERWRITTEN instead of FILE_WAS_SUPERSEDED;
//   - a DIRECTORY_FILE create for a name that did not exist was created as a
//     regular file first and refused afterwards, leaving a zero-byte file from
//     a request that failed;
//   - an SMB2_CREATE_TIMEWARP_TOKEN was ignored, so a snapshot mount browsed
//     and copied live data while its UI said it was showing a snapshot.
//
// The tests drive handleCreate directly, which is where all four live.

// newCreatePathDispatcher is newTestDispatcher plus a Connection, because
// handleRead reads MaxIOSize off it and these tests read through the handles
// they open.
func newCreatePathDispatcher(t *testing.T, shareDir string) (*Dispatcher, *Session, *Tree) {
	t.Helper()
	d, sess, tree := newTestDispatcher(t, shareDir)
	d.Conn = &Connection{MaxIOSize: 1 << 20}
	return d, sess, tree
}

// doCreate drives one CREATE and returns the status plus the raw response body
// (the SMB2 header stripped). The body is returned raw so a test can assert on
// fields readCreateResponse does not decode — CreateAction above all.
func doCreate(t *testing.T, d *Dispatcher, sess *Session, tree *Tree,
	name string, disposition, options, access uint32, ctxs []byte) (smb2.Status, []byte) {
	t.Helper()
	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody(name, disposition, options, access, ctxs), sess)
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize {
		t.Fatalf("CREATE %q: response too short (%d bytes)", name, len(frame))
	}
	hdr, err := smb2.DecodeHeader(frame[4 : 4+smb2.HeaderSize])
	if err != nil {
		t.Fatalf("CREATE %q: decode header: %v", name, err)
	}
	return smb2.Status(hdr.Status), frame[4+smb2.HeaderSize:]
}

// mustCreate fails the test unless the CREATE succeeded.
func mustCreate(t *testing.T, d *Dispatcher, sess *Session, tree *Tree,
	name string, disposition, options, access uint32) []byte {
	t.Helper()
	status, body := doCreate(t, d, sess, tree, name, disposition, options, access, nil)
	if status != smb2.StatusSuccess {
		t.Fatalf("CREATE %q = %#x, want success", name, uint32(status))
	}
	return body
}

// CREATE response accessors (MS-SMB2 §2.2.14, fixed part).
func createAction(body []byte) uint32    { return binary.LittleEndian.Uint32(body[4:]) }
func createEndOfFile(body []byte) uint64 { return binary.LittleEndian.Uint64(body[48:]) }
func createAttrs(body []byte) uint32     { return binary.LittleEndian.Uint32(body[56:]) }
func createFileID(body []byte) (id [16]byte) {
	copy(id[:], body[64:80])
	return id
}

// readAll reads length bytes from fid through handleRead and returns them.
func readAll(t *testing.T, d *Dispatcher, sess *Session, fid [16]byte, length uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	d.handleRead(&buf, smb2.Header{Command: smb2.CommandRead}, buildReadBody(fid, 0, length), sess)
	frame := buf.Bytes()
	if len(frame) < 4+smb2.HeaderSize+16 {
		t.Fatalf("READ: response too short (%d bytes)", len(frame))
	}
	hdr, err := smb2.DecodeHeader(frame[4 : 4+smb2.HeaderSize])
	if err != nil {
		t.Fatalf("READ: decode header: %v", err)
	}
	if smb2.Status(hdr.Status) != smb2.StatusSuccess {
		t.Fatalf("READ = %#x, want success", hdr.Status)
	}
	body := frame[4+smb2.HeaderSize:]
	// DataOffset is one byte, absolute from the start of the SMB2 header.
	off := int(body[2]) - smb2.HeaderSize
	n := int(binary.LittleEndian.Uint32(body[4:]))
	if off < 0 || off+n > len(body) {
		t.Fatalf("READ: data offset %d length %d outside a %d-byte body", off, n, len(body))
	}
	return body[off : off+n]
}

// closeFID closes a handle so the test leaves no share-mode reservation behind.
func closeFID(t *testing.T, d *Dispatcher, sess *Session, tree *Tree, fid [16]byte) {
	t.Helper()
	var buf bytes.Buffer
	d.handleClose(&buf, smb2.Header{Command: smb2.CommandClose, TreeID: tree.ID},
		buildCloseBody(fid), sess)
	if st := respStatus(t, &buf); st != smb2.StatusSuccess {
		t.Fatalf("CLOSE = %#x, want success", uint32(st))
	}
}

// --- Defect 1: in-share symlinks ---

// TestFixCreatePath_InShareSymlinkOpensTarget is the core regression: opening a
// symlink whose target is inside the share must open the TARGET — its bytes and
// its size, not the link's own.
func TestFixCreatePath_InShareSymlinkOpensTarget(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	const content = "the target's real content"
	if err := os.WriteFile(filepath.Join(dir, "target.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// A relative link, which is what a user's `ln -s` produces.
	if err := os.Symlink("target.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	// Before the fix this was STATUS_ACCESS_DENIED: O_NOFOLLOW on the link.
	body := mustCreate(t, d, sess, tree, "link.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData)

	// The size must be the target's, not the length of the string
	// "target.txt" — that mismatch is what made Finder show a plausible file
	// that could never be read.
	if got := createEndOfFile(body); got != uint64(len(content)) {
		t.Errorf("EndOfFile = %d, want %d (the target's size, not the link's)", got, len(content))
	}
	if attrs := createAttrs(body); attrs&smb2.FileAttrDirectory != 0 {
		t.Errorf("FileAttributes = %#x, want a non-directory", attrs)
	}

	fid := createFileID(body)
	if got := string(readAll(t, d, sess, fid, 128)); got != content {
		t.Errorf("READ through the symlink = %q, want %q", got, content)
	}
	closeFID(t, d, sess, tree, fid)
}

// TestFixCreatePath_InShareSymlinkToDirOpens covers the other half: a link to a
// directory inside the share has to open as a directory, or the handle reports
// a file and every enumeration of it fails.
func TestFixCreatePath_InShareSymlinkToDirOpens(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	if err := os.Mkdir(filepath.Join(dir, "realdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("realdir", filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}

	body := mustCreate(t, d, sess, tree, "dirlink",
		smb2.CreateDispositionOpen, smb2.CreateOptDirectoryFile, smb2.AccessFileReadData)
	if attrs := createAttrs(body); attrs&smb2.FileAttrDirectory == 0 {
		t.Errorf("FileAttributes = %#x, want FILE_ATTRIBUTE_DIRECTORY", attrs)
	}
	closeFID(t, d, sess, tree, createFileID(body))
}

// TestFixCreatePath_EscapingSymlinkStillRefused is the containment guard that
// has to survive the fix above: following a link is only ever allowed to land
// inside the share. Both the link itself and a path THROUGH it must be refused,
// and nothing outside may be opened.
func TestFixCreatePath_EscapingSymlinkStillRefused(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escapedir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "escapefile")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"escapedir", "escapefile", `escapedir\secret.txt`} {
		status, _ := doCreate(t, d, sess, tree, name,
			smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData, nil)
		if status != smb2.StatusAccessDenied {
			t.Errorf("CREATE %q = %#x, want STATUS_ACCESS_DENIED — the share was escaped",
				name, uint32(status))
		}
	}
	if n := sess.OpenCount(); n != 0 {
		t.Errorf("session holds %d opens after three refused CREATEs, want 0", n)
	}

	// A creating disposition must not reach outside either: it would plant a
	// file in a directory the share does not export.
	status, _ := doCreate(t, d, sess, tree, `escapedir\planted.txt`,
		smb2.CreateDispositionOpenIf, 0, smb2.AccessFileWriteData, nil)
	if status != smb2.StatusAccessDenied {
		t.Errorf("creating CREATE through an escaping link = %#x, want STATUS_ACCESS_DENIED", uint32(status))
	}
	if _, err := os.Lstat(filepath.Join(outside, "planted.txt")); err == nil {
		t.Error("a refused CREATE planted a file outside the share")
	}
}

// TestFixCreatePath_DanglingSymlinkStatus pins the status for a link that
// cannot be followed, and pins it to the SAME value the errno path reports.
// The two disagreed: ResolveSecure folded a broken link into ErrTraversal →
// ACCESS_DENIED, while an O_NOFOLLOW open of one produced ELOOP →
// OBJECT_PATH_NOT_FOUND. A client saw a permission problem for a file that was
// simply not there.
func TestFixCreatePath_DanglingSymlinkStatus(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	if err := os.Symlink("gone.txt", filepath.Join(dir, "broken.txt")); err != nil {
		t.Fatal(err)
	}

	status, _ := doCreate(t, d, sess, tree, "broken.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData, nil)
	if status != smb2.StatusObjectPathNotFound {
		t.Errorf("CREATE of a dangling link = %#x, want STATUS_OBJECT_PATH_NOT_FOUND (%#x)",
			uint32(status), uint32(smb2.StatusObjectPathNotFound))
	}

	// The consistency itself, not just this one call site.
	if got, want := statusFromResolveErr(vfs.ErrDanglingLink), statusFromErr(syscall.ELOOP); got != want {
		t.Errorf("unfollowable symlink reports %#x from the resolver and %#x from errno: pick one",
			uint32(got), uint32(want))
	}
	// A proven escape is a different answer on purpose.
	if got := statusFromResolveErr(vfs.ErrTraversal); got != smb2.StatusAccessDenied {
		t.Errorf("traversal reports %#x, want STATUS_ACCESS_DENIED", uint32(got))
	}
}

// --- Defect 2: FILE_SUPERSEDE ---

// TestFixCreatePath_SupersedeReportsSuperseded checks the action code and that
// supersede still does what it says to the contents.
func TestFixCreatePath_SupersedeReportsSuperseded(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	path := filepath.Join(dir, "doc.txt")
	if err := os.WriteFile(path, []byte("old contents"), 0o644); err != nil {
		t.Fatal(err)
	}

	body := mustCreate(t, d, sess, tree, "doc.txt",
		smb2.CreateDispositionSupersede, 0, smb2.AccessFileReadData|smb2.AccessFileWriteData)
	if got := createAction(body); got != smb2.CreateActionSuperseded {
		t.Errorf("CreateAction = %d, want FILE_WAS_SUPERSEDED (%d)", got, smb2.CreateActionSuperseded)
	}
	if got := createEndOfFile(body); got != 0 {
		t.Errorf("EndOfFile = %d after a supersede, want 0", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after supersede: %v", err)
	}
	if st.Size() != 0 {
		t.Errorf("file is %d bytes after a supersede, want 0", st.Size())
	}
	closeFID(t, d, sess, tree, createFileID(body))
}

// TestFixCreatePath_SupersedeOfNewFileReportsCreated: superseding a name that
// does not exist creates it, and creating is FILE_WAS_CREATED, not SUPERSEDED —
// there was nothing to supersede.
func TestFixCreatePath_SupersedeOfNewFileReportsCreated(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	body := mustCreate(t, d, sess, tree, "fresh.txt",
		smb2.CreateDispositionSupersede, 0, smb2.AccessFileWriteData)
	if got := createAction(body); got != smb2.CreateActionCreated {
		t.Errorf("CreateAction = %d, want FILE_WAS_CREATED (%d)", got, smb2.CreateActionCreated)
	}
	closeFID(t, d, sess, tree, createFileID(body))
}

// TestFixCreatePath_OverwriteIfStillReportsOverwritten guards the arm SUPERSEDE
// was split out of.
func TestFixCreatePath_OverwriteIfStillReportsOverwritten(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := mustCreate(t, d, sess, tree, "doc.txt",
		smb2.CreateDispositionOverwriteIf, 0, smb2.AccessFileWriteData)
	if got := createAction(body); got != smb2.CreateActionOverwritten {
		t.Errorf("CreateAction = %d, want FILE_WAS_OVERWRITTEN (%d)", got, smb2.CreateActionOverwritten)
	}
	closeFID(t, d, sess, tree, createFileID(body))
}

// --- Defect 3: a failed CREATE must leave nothing behind ---

// TestFixCreatePath_FailedDirectoryCreateLeavesNoFile is the stray-file
// regression. Every one of these requests must fail, and the share must be
// exactly as empty afterwards as it was before.
func TestFixCreatePath_FailedDirectoryCreateLeavesNoFile(t *testing.T) {
	cases := []struct {
		name        string
		disposition uint32
		options     uint32
	}{
		// The reported one: OVERWRITE_IF/SUPERSEDE have no mkdir branch, so
		// they created a regular FILE and the DIRECTORY_FILE check refused the
		// request afterwards — with the file already on disk.
		{"overwrite_if", smb2.CreateDispositionOverwriteIf, smb2.CreateOptDirectoryFile},
		{"supersede", smb2.CreateDispositionSupersede, smb2.CreateOptDirectoryFile},
		{"overwrite", smb2.CreateDispositionOverwrite, smb2.CreateOptDirectoryFile},
		// The same bug in its other form: FILE_CREATE mkdir'd the directory and
		// the NON_DIRECTORY_FILE check then failed the request, leaving the
		// new directory behind.
		{"create_both_options", smb2.CreateDispositionCreate,
			smb2.CreateOptDirectoryFile | smb2.CreateOptNonDirFile},
		{"open_if_both_options", smb2.CreateDispositionOpenIf,
			smb2.CreateOptDirectoryFile | smb2.CreateOptNonDirFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			d, sess, tree := newCreatePathDispatcher(t, dir)

			status, _ := doCreate(t, d, sess, tree, "newdir",
				tc.disposition, tc.options, smb2.AccessFileReadData|smb2.AccessFileWriteData, nil)
			if status == smb2.StatusSuccess {
				t.Fatalf("CREATE succeeded, want a failure")
			}
			if _, err := os.Lstat(filepath.Join(dir, "newdir")); !os.IsNotExist(err) {
				t.Errorf("a failed CREATE left %q on disk (lstat err = %v)", "newdir", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("share holds %d entries after a failed CREATE, want 0", len(entries))
			}
			if n := sess.OpenCount(); n != 0 {
				t.Errorf("session holds %d opens after a failed CREATE, want 0", n)
			}
		})
	}
}

// TestFixCreatePath_DirectoryCreateStillWorks is the other side of the coin: the
// dispositions that CAN create a directory still do, and still report the right
// action. A fix that refuses too much would be invisible to the test above.
func TestFixCreatePath_DirectoryCreateStillWorks(t *testing.T) {
	for _, disposition := range []uint32{smb2.CreateDispositionCreate, smb2.CreateDispositionOpenIf} {
		dir := t.TempDir()
		d, sess, tree := newCreatePathDispatcher(t, dir)

		body := mustCreate(t, d, sess, tree, "newdir", disposition,
			smb2.CreateOptDirectoryFile, smb2.AccessFileReadData)
		if got := createAction(body); got != smb2.CreateActionCreated {
			t.Errorf("disposition %d: CreateAction = %d, want FILE_WAS_CREATED", disposition, got)
		}
		if got := createAttrs(body); got&smb2.FileAttrDirectory == 0 {
			t.Errorf("disposition %d: FileAttributes = %#x, want FILE_ATTRIBUTE_DIRECTORY", disposition, got)
		}
		fi, err := os.Lstat(filepath.Join(dir, "newdir"))
		if err != nil || !fi.IsDir() {
			t.Errorf("disposition %d: no directory on disk (err = %v)", disposition, err)
		}
		closeFID(t, d, sess, tree, createFileID(body))
	}
}

// TestFixCreatePath_TypeMismatchStatuses pins the statuses the moved checks
// report for an object that exists with the wrong type — including the one
// precedence the move had to preserve: FILE_CREATE on a taken name is a
// collision whatever the type, which is the answer a client uses to decide the
// name is in use.
func TestFixCreatePath_TypeMismatchStatuses(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		target      string
		disposition uint32
		options     uint32
		want        smb2.Status
	}{
		{"dir option on a file", "file.txt", smb2.CreateDispositionOpen,
			smb2.CreateOptDirectoryFile, smb2.StatusNotADirectory},
		{"non-dir option on a directory", "dir", smb2.CreateDispositionOpen,
			smb2.CreateOptNonDirFile, smb2.StatusFileIsADirectory},
		{"create over a file keeps reporting collision", "file.txt", smb2.CreateDispositionCreate,
			smb2.CreateOptDirectoryFile, smb2.StatusObjectNameCollision},
		{"create over a directory keeps reporting collision", "dir", smb2.CreateDispositionCreate,
			smb2.CreateOptNonDirFile, smb2.StatusObjectNameCollision},
		{"both type options at once", "file.txt", smb2.CreateDispositionOpen,
			smb2.CreateOptDirectoryFile | smb2.CreateOptNonDirFile, smb2.StatusInvalidParameter},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := doCreate(t, d, sess, tree, tc.target,
				tc.disposition, tc.options, smb2.AccessFileReadData, nil)
			if status != tc.want {
				t.Errorf("CREATE %q = %#x, want %#x", tc.target, uint32(status), uint32(tc.want))
			}
		})
	}
}

// --- Defect 4: the timewarp token ---

// twrpCtx builds the create context macOS attaches to every non-IPC CREATE on a
// snapshot mount: name "TWrp" (0x54577270), 8 bytes of FILETIME.
func twrpCtx(filetime uint64) []byte {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], filetime)
	return smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("TWrp"), Data: data[:]}})
}

// TestFixCreatePath_TimewarpRefused: the server has no previous versions, so
// MS-SMB2 §3.3.5.9.5 says fail with STATUS_NOT_FOUND. Answering the live file
// instead is what let `mount_smbfs -o snapshot=<time>` copy today's data while
// claiming to show a snapshot.
func TestFixCreatePath_TimewarpRefused(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("live data"), 0o644); err != nil {
		t.Fatal(err)
	}

	status, _ := doCreate(t, d, sess, tree, "doc.txt",
		smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData, twrpCtx(132000000000000000))
	if status != smb2.StatusNotFound {
		t.Fatalf("CREATE with a timewarp token = %#x, want STATUS_NOT_FOUND (%#x)",
			uint32(status), uint32(smb2.StatusNotFound))
	}
	if n := sess.OpenCount(); n != 0 {
		t.Errorf("a refused timewarp CREATE left %d opens behind, want 0", n)
	}
}

// TestFixCreatePath_TimewarpNeverEchoed is the constraint that makes the
// refusal usable. The client's response-context parser has no case for a
// timewarp name and its default arm is `error = EBADRPC; goto bad;`, so echoing
// the context back would fail the whole CREATE fatally instead of with a status
// the client can act on. Nothing named TWrp may appear in the response.
func TestFixCreatePath_TimewarpNeverEchoed(t *testing.T) {
	dir := t.TempDir()
	d, sess, tree := newCreatePathDispatcher(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("live data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sent the way macOS sends it: alongside the contexts it always asks for.
	ctxs := smb2.EncodeCreateContexts([]smb2.CreateContext{
		{Name: []byte("MxAc")},
		{Name: []byte("TWrp"), Data: make([]byte, 8)},
		{Name: []byte("QFid")},
	})
	var buf bytes.Buffer
	d.handleCreate(&buf, smb2.Header{Command: smb2.CommandCreate, TreeID: tree.ID},
		buildCreateBody("doc.txt", smb2.CreateDispositionOpen, 0, smb2.AccessFileReadData, ctxs), sess)
	frame := buf.Bytes()

	if st := respStatus(t, &buf); st != smb2.StatusNotFound {
		t.Fatalf("CREATE = %#x, want STATUS_NOT_FOUND", uint32(st))
	}
	if bytes.Contains(frame, []byte("TWrp")) {
		t.Error("the response carries a TWrp context: macOS fails that CREATE with EBADRPC")
	}
	// Nor any of the contexts that would normally be answered — the request
	// was refused, so it has no response contexts at all.
	for _, tag := range []string{"MxAc", "QFid", "AAPL"} {
		if bytes.Contains(frame, []byte(tag)) {
			t.Errorf("the refused CREATE answered the %s context", tag)
		}
	}
}

// TestFixCreatePath_TimewarpDetection covers the tag itself. The four bytes are
// 0x54 0x57 0x72 0x70 — capital W — and Apple's header comments them "Twrp",
// which is the spelling a reader is likely to copy.
func TestFixCreatePath_TimewarpDetection(t *testing.T) {
	if got := binary.BigEndian.Uint32(tagTwrp); got != 0x54577270 {
		t.Errorf("tagTwrp = %#x, want SMB2_CREATE_TIMEWARP_TOKEN (0x54577270)", got)
	}
	if !hasTimewarpContext(twrpCtx(0)) {
		t.Error("hasTimewarpContext missed a lone timewarp context")
	}
	mixed := smb2.EncodeCreateContexts([]smb2.CreateContext{
		{Name: []byte("DH2Q"), Data: make([]byte, 32)},
		{Name: []byte("TWrp"), Data: make([]byte, 8)},
	})
	if !hasTimewarpContext(mixed) {
		t.Error("hasTimewarpContext missed a timewarp context that was not first")
	}
	if hasTimewarpContext(nil) {
		t.Error("hasTimewarpContext claims an empty context blob carries a timewarp token")
	}
	if hasTimewarpContext(smb2.EncodeCreateContexts([]smb2.CreateContext{{Name: []byte("MxAc")}})) {
		t.Error("hasTimewarpContext fired on a context that is not a timewarp token")
	}
}
