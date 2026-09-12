package parent

import (
	"encoding/binary"
	"io"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// pendingResponses buffers the responses one inbound frame's chain produces so
// that the members of a compound request can be answered with a single
// compounded frame rather than one frame each.
//
// It matters more than it looks. The macOS client latches a flag the first time
// it sees a non-compound reply to a compound request — "Once set, this remains
// set forever" (SMBClient, smb_iod.c, SMBV_NON_COMPOUND_REPLIES, a workaround
// for a NetApp bug) — and from then on every reply on that connection takes a
// slower path that walks the outstanding request chains, waking a chain only
// once every one of its members has replied.
type pendingResponses struct {
	msgs []pendingMsg
}

// pendingMsg is one finished but unsealed SMB2 response. buf holds
// transport.FrameHeaderSize bytes of reserved NBSS headroom followed by the
// message itself.
//
// sess and encrypt are captured when the response is produced rather than when
// it is sent, because they decide which frame the response can share: one
// frame carries one session (the transform header names a single SessionId,
// and each member's signature uses that session's key) and one encryption
// decision.
type pendingMsg struct {
	buf     []byte
	sess    *Session
	encrypt bool
}

// emit hands one finished response to this frame's chain buffer.
//
// A Dispatcher that is not running a chain — a unit test driving a single
// handler against a plain buffer — has no buffer, and the response goes
// straight out as its own frame, exactly as it did before compounding existed.
// buf must carry transport.FrameHeaderSize bytes of NBSS headroom at the front.
func (d *Dispatcher) emit(rw io.Writer, sess *Session, buf []byte) {
	encrypt := d.willEncryptResponse(sess)
	if d.pending != nil {
		d.pending.msgs = append(d.pending.msgs, pendingMsg{buf: buf, sess: sess, encrypt: encrypt})
		return
	}
	_ = d.sealAndSend(rw, sess, buf, encrypt)
}

// flush sends everything this frame's chain produced. It is safe to call on a
// chain that produced nothing (a lone SMB2_CANCEL, which is answered by
// completing the request it names rather than with a response of its own).
func (d *Dispatcher) flush(rw io.Writer) {
	if d.pending == nil {
		return
	}
	msgs := d.pending.msgs
	d.pending.msgs = nil
	for len(msgs) > 0 {
		// Consecutive members that share a session and an encryption decision
		// travel together. Unrelated compounded requests may legally name
		// different sessions, which cannot share a transform header or a
		// signing key, so those are answered in separate frames.
		n := 1
		for n < len(msgs) && msgs[n].sess == msgs[0].sess && msgs[n].encrypt == msgs[0].encrypt {
			n++
		}
		d.sendCompound(rw, msgs[:n])
		msgs = msgs[n:]
	}
}

// sendCompound writes one group of responses as a single NBSS frame.
//
// MS-SMB2 §3.3.4.1: every member except the last is padded out to the next
// 8-byte boundary and carries that padded length in its NextCommand; the last
// carries 0 and no padding.
//
// Signing is per member, and is computed after NextCommand has been written,
// over exactly the NextCommand bytes the field announces — padding included.
// That is not a guess: the macOS client's verifier takes the length to hash
// straight from the field (SMBClient, smb_crypt.c, smb3_verify:
// "if (nextCmdOffset != 0) reply_len = nextCmdOffset"), and for the final
// member, whose NextCommand is 0, it hashes everything left in the frame —
// which is why the last member must not be padded.
//
// Encryption is the other way round: the transform header wraps the whole
// compounded frame, not each member, and a signature under it would be
// redundant (MS-SMB2 §3.3.4.1.4), so encrypted members are not signed.
func (d *Dispatcher) sendCompound(rw io.Writer, msgs []pendingMsg) {
	sess, encrypt := msgs[0].sess, msgs[0].encrypt
	if len(msgs) == 1 {
		_ = d.sealAndSend(rw, sess, msgs[0].buf, encrypt)
		return
	}

	last := len(msgs) - 1
	total := 0
	for i := range msgs {
		total += compoundMemberLen(msgs[i].buf, i == last)
	}

	out := make([]byte, transport.FrameHeaderSize+total)
	off := transport.FrameHeaderSize
	for i := range msgs {
		src := msgs[i].buf[transport.FrameHeaderSize:]
		n := compoundMemberLen(msgs[i].buf, i == last)
		msg := out[off : off+n]
		// out is freshly allocated, so the bytes past the copy — the padding —
		// are already zero.
		copy(msg, src)
		next := uint32(0)
		if i != last {
			next = uint32(n)
		}
		binary.LittleEndian.PutUint32(msg[smb2.NextCommandOffset:], next)
		if !encrypt {
			d.signResponse(sess, msg)
		}
		off += n
	}

	if encrypt {
		_ = d.sendEncrypted(rw, sess, out[transport.FrameHeaderSize:])
		return
	}
	_ = d.sendPreframed(rw, out)
}

// compoundMemberLen is how many bytes a member occupies inside a compounded
// frame: its own length, rounded up to an 8-byte boundary unless it is last.
func compoundMemberLen(buf []byte, last bool) int {
	n := len(buf) - transport.FrameHeaderSize
	if last {
		return n
	}
	return padTo8(n)
}

// sealAndSend signs or encrypts one standalone message and queues it.
// buf carries transport.FrameHeaderSize bytes of NBSS headroom at the front.
func (d *Dispatcher) sealAndSend(rw io.Writer, sess *Session, buf []byte, encrypt bool) error {
	msg := buf[transport.FrameHeaderSize:]
	if encrypt {
		return d.sendEncrypted(rw, sess, msg)
	}
	d.signResponse(sess, msg)
	return d.sendPreframed(rw, buf)
}

// signResponse signs msg in place when the session has a signing key. A
// message going out under a transform header is never signed: the AEAD already
// authenticates it (MS-SMB2 §3.3.4.1.4).
func (d *Dispatcher) signResponse(sess *Session, msg []byte) {
	if sess == nil || len(sess.SigningKey) == 0 || d.Conn == nil {
		return
	}
	smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, msg)
}

// sendEncrypted wraps msg — which may be a whole compounded frame — in one SMB3
// transform header and queues the result.
func (d *Dispatcher) sendEncrypted(rw io.Writer, sess *Session, msg []byte) error {
	enc, err := smb3.EncryptTransform(uint16(d.Conn.Selection.Cipher), sess.S2CCipherKey, sess.ID, msg)
	if err != nil {
		if d.Log != nil {
			d.Log.Warn("response encryption failed", "err", err)
		}
		return err
	}
	// EncryptTransform builds the transform header into a buffer of its own,
	// so the frame header has to be prepended here.
	buf := make([]byte, transport.FrameHeaderSize+len(enc))
	copy(buf[transport.FrameHeaderSize:], enc)
	return d.sendPreframed(rw, buf)
}

// sendPreframed hands a buffer whose first transport.FrameHeaderSize bytes are
// reserved NBSS headroom to the connection's writer goroutine.
//
// Without a writer — a unit test driving a handler against a plain buffer — it
// writes inline instead. That is the only remaining path on which a response
// touches the destination from the goroutine that produced it.
func (d *Dispatcher) sendPreframed(rw io.Writer, buf []byte) error {
	if d.out == nil {
		return transport.WritePreframed(rw, buf)
	}
	if err := transport.PutFrameHeader(buf); err != nil {
		return err
	}
	return d.out.send(buf)
}
