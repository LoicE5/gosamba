package parent

import "time"

// Waiting out a transient sharing conflict.
//
// MS-SMB2 §3.3.5.9 says a CREATE that loses the sharing-access check is
// answered STATUS_SHARING_VIOLATION, and gosamba does. What it has no way to
// do is make the conflicting handle go away: ksmbd clears the same conflict by
// breaking the holder's oplock (fs/smb/server/oplock.c, smb_grant_oplock), and
// gosamba grants neither oplocks nor leases, so a conflict it refuses is a
// conflict it never revisits.
//
// That matters because of how macOS deletes. smbfs opens the victim deny-all
// — the only NTCREATEX_SHARE_ACCESS_NONE open in the whole client
// (SMBClient kernel/smbfs/smbfs_smb_2.c, radar <17346821>) — so *any*
// concurrent open of that file refuses the delete. And the client never
// retries: kernel/netsmb/smb_subr.c maps STATUS_SHARING_VIOLATION straight to
// EBUSY and hands it to userspace. With two machines on one share, a few
// milliseconds of overlap between one client's read and another's delete is
// enough to fail rm — which leaves .git/index.lock on disk and breaks the
// repository until someone removes it by hand.
//
// So the server absorbs the window. A refused CREATE parks until the
// conflicting reservation is released or the deadline passes, whichever comes
// first.

const (
	// sharingViolationWait bounds how long a single wait parks before the
	// caller is told. Measured overlaps between two macOS clients are
	// single-digit milliseconds, and the wait is edge-triggered, so the common
	// case returns almost immediately; this is only the ceiling for a holder
	// that never lets go. It is far inside any client's request timeout.
	//
	// A CREATE parks at most once: the pre-open check for a truncating
	// disposition (checkLocked, run via sharedShareModes.check in
	// dispatch.go) does not wait at all — see the comment at its call site —
	// so acquireShareMode below is the only wait on the path.
	sharingViolationWait = 250 * time.Millisecond

	// maxSharingWaits bounds how many CREATEs one connection may park at once.
	// A parked CREATE occupies a worker-pool slot, and connPool.submit stops
	// the connection reading frames once every slot is busy — so without a cap
	// a single contended file could stall a whole mount. Past the cap the
	// answer is the immediate refusal it has always been.
	maxSharingWaits = 4
)

// A parked CREATE holds one of the connection's worker-pool slots, so the cap
// must leave slots free for the CLOSE that would release the conflict — or a
// connection could park its whole pool on a file only it can free. This fails
// to compile if minConnWorkers ever drops to maxSharingWaits or below.
const _ = uint(minConnWorkers - maxSharingWaits - 1)

// beginSharingWait claims one of this connection's parking slots, reporting
// false when they are all taken (or when there is no Connection at all, which
// is a unit test driving one handler).
func (d *Dispatcher) beginSharingWait() bool {
	if d == nil || d.Conn == nil {
		return false
	}
	if d.Conn.sharingWaits.Add(1) > maxSharingWaits {
		d.Conn.sharingWaits.Add(-1)
		return false
	}
	return true
}

func (d *Dispatcher) endSharingWait() {
	if d != nil && d.Conn != nil {
		d.Conn.sharingWaits.Add(-1)
	}
}

// waitForShareMode runs try until it succeeds, the deadline passes, or this
// connection has no parking slot left.
//
// try must be atomic in the table: it either takes the reservation or hands
// back a registration for the next release on that key. Nothing here touches
// the filesystem — the caller keeps whatever descriptor it already opened, and
// a retry is a map lookup plus one Fstat per surviving entry (entryLive).
func (d *Dispatcher) waitForShareMode(try func() (bool, *shareWaiter)) bool {
	ok, w := try()
	if ok {
		return true
	}
	if !d.beginSharingWait() {
		sharedShareModes.unwait(w)
		return false
	}
	defer d.endSharingWait()

	// One timer for the whole wait, not one per retry, so the total stays
	// bounded however many times the file changes hands underneath us.
	deadline := time.NewTimer(sharingViolationWait)
	defer deadline.Stop()
	for {
		// select picks randomly among ready cases, and once deadline.C has
		// fired it stays ready alongside w.ch. Without this non-blocking
		// probe, a file whose reservation changes hands every few
		// milliseconds could keep winning the random pick on w.ch and
		// extend the wait past the ceiling by a geometric number of cycles.
		select {
		case <-deadline.C:
			sharedShareModes.unwait(w)
			return false
		default:
		}
		select {
		case <-w.ch:
			// Woken: the registration is already gone from the table.
		case <-deadline.C:
			sharedShareModes.unwait(w)
			return false
		}
		if ok, w = try(); ok {
			return true
		}
	}
}

// acquireShareMode reserves open's deny mode, waiting out a transient conflict.
func (d *Dispatcher) acquireShareMode(key fileKey, open *Open, desired, share uint32) bool {
	return d.waitForShareMode(func() (bool, *shareWaiter) {
		return sharedShareModes.acquireOrWait(key, open, desired, share)
	})
}
