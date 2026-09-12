package parent

import (
	"bytes"

	"github.com/ahmetozer/gosamba/internal/smb2"
)

// tagTwrp is SMB2_CREATE_TIMEWARP_TOKEN (MS-SMB2 §2.2.13.2.7): the create
// context a client attaches to open the version of a file that existed at a
// given point in time, i.e. the copy in a snapshot rather than the live one.
//
// The four bytes are 0x54 0x57 0x72 0x70 — capital T, capital W. Apple's header
// spells the comment "Twrp" next to that same constant
// (SMBClient kernel/netsmb/smb_2.h: SMB2_CREATE_TIMEWARP_TOKEN 0x54577270),
// so matching on the lowercase spelling would never fire.
var tagTwrp = []byte("TWrp")

// hasTimewarpContext reports whether a CREATE's create-context blob carries a
// timewarp token.
//
// This server exposes no previous versions: there is no snapshot store behind a
// share, and FSCTL_SRV_ENUMERATE_SNAPSHOTS reports none. MS-SMB2 §3.3.5.9.5 is
// explicit about what that means — a CREATE carrying this context "MUST" be
// failed with STATUS_NOT_FOUND when the share has no previous versions — and
// that is not pedantry here. macOS sets the token on EVERY non-IPC CREATE once
// the session is a snapshot mount:
//
//	if ((SS_TO_SESSION(share)->session_misc_flags & SMBV_MNT_SNAPSHOT) &&
//	    (strcmp(share->ss_name, "IPC$") != 0)) {
//	        createp->flags |= SMB2_CREATE_ADD_TIME_WARP;
//	    }
//
// (SMBClient kernel/netsmb/smb_smb_2.c). Ignoring the token therefore does not
// degrade gracefully: `mount_smbfs -o snapshot=<time>` browses and copies the
// CURRENT contents of every file while the Finder window says it is showing the
// snapshot. Silently answering with today's data is worse than refusing.
//
// The refusal must be a status, never a response context. The client's
// response-context parser has no case for a timewarp name, and its default arm
// is `error = EBADRPC; goto bad;` — echoing the context back would fail the
// CREATE fatally and unrecoverably instead of with the status the spec asks
// for.
func hasTimewarpContext(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	found := false
	smb2.IterateCreateContexts(raw, func(c smb2.CreateContext) bool {
		if bytes.Equal(c.Name, tagTwrp) {
			found = true
			return false
		}
		return true
	})
	return found
}
