// Package discovery provides mDNS/Bonjour service advertisement so Apple
// clients (macOS Finder, iOS) can auto-discover the gosamba SMB server.
package discovery

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	mdnsAddr     = "224.0.0.251"
	mdnsPort     = 5353
	mdnsAddrPort = "224.0.0.251:5353"
	smbService   = "_smb._tcp.local."
	mdnsTTL      = 120 // seconds
)

// advertiser holds the state for the mDNS responder.
type advertiser struct {
	conns  []interfaceConn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// interfaceConn keeps a multicast socket together with the IPv4 addresses of
// the interface it joined. mDNS A records must describe the path on which a
// response is sent, rather than every address configured on the host.
type interfaceConn struct {
	conn *net.UDPConn
	ips  []net.IP
}

func (c interfaceConn) buildResponse(query dnsmessage.Message, instance, hostname string, port int) ([]byte, bool) {
	return buildResponse(query, instance, hostname, c.ips, port)
}

// Close shuts down the advertiser and all listening sockets.
func (a *advertiser) Close() error {
	a.cancel()
	for _, c := range a.conns {
		c.conn.Close()
	}
	a.wg.Wait()
	return nil
}

// Advertise starts an mDNS responder that announces the SMB service on all
// available multicast-capable IPv4 interfaces. It returns an io.Closer that
// stops the responder. The context cancellation also stops it.
//
// instance is the Bonjour service instance name (e.g. "MyServer").
// hostname is the hostname without the ".local." suffix.
// port is the TCP port the SMB server listens on.
func Advertise(ctx context.Context, instance, hostname string, port int, log *slog.Logger) (io.Closer, error) {
	if log == nil {
		log = slog.Default()
	}

	group := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}
	ifaces, err := multicastIfaces()
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, &net.OpError{Op: "join multicast", Net: "udp4", Err: errNoMulticast}
	}

	rctx, cancel := context.WithCancel(ctx)

	a := &advertiser{cancel: cancel}

	for _, candidate := range ifaces {
		conn, err := net.ListenMulticastUDP("udp4", &candidate.iface, group)
		if err != nil {
			log.Debug("mDNS: cannot join multicast on interface", "iface", candidate.iface.Name, "err", err)
			continue
		}
		endpoint := interfaceConn{conn: conn, ips: candidate.ips}
		a.conns = append(a.conns, endpoint)

		a.wg.Add(1)
		go func(endpoint interfaceConn) {
			defer a.wg.Done()
			serveLoop(rctx, endpoint, instance, hostname, port, log)
		}(endpoint)
	}

	if len(a.conns) == 0 {
		cancel()
		return nil, &net.OpError{Op: "join multicast", Net: "udp4", Err: errNoMulticast}
	}

	log.Info("mDNS: advertising SMB service",
		"instance", instance,
		"hostname", hostname+".local.",
		"port", port,
		"interfaces", len(a.conns),
	)

	// Send an initial unsolicited announcement (gratuitous mDNS).
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		t := time.NewTimer(100 * time.Millisecond)
		defer t.Stop()
		select {
		case <-rctx.Done():
			return
		case <-t.C:
		}
		announce(a.conns, instance, hostname, port, log)
	}()

	return a, nil
}

// serveLoop reads mDNS queries from conn and answers those matching _smb._tcp.
func serveLoop(ctx context.Context, endpoint interfaceConn, instance, hostname string, port int, log *slog.Logger) {
	buf := make([]byte, 4096)
	multicast := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoint.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := endpoint.conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return
		}

		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if msg.Header.Response {
			// Ignore responses from others.
			continue
		}

		resp, matched := endpoint.buildResponse(msg, instance, hostname, port)
		if !matched || len(resp) == 0 {
			continue
		}

		// Send response to mDNS multicast group.
		if _, err := endpoint.conn.WriteToUDP(resp, multicast); err != nil {
			log.Debug("mDNS: write response error", "err", err)
		}
	}
}

// announce sends an unsolicited PTR+SRV+TXT+A announcement to all open connections.
func announce(conns []interfaceConn, instance, hostname string, port int, log *slog.Logger) {
	query := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustNewName(smbService),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	multicast := &net.UDPAddr{IP: net.ParseIP(mdnsAddr), Port: mdnsPort}
	for _, endpoint := range conns {
		resp, _ := endpoint.buildResponse(query, instance, hostname, port)
		if len(resp) == 0 {
			continue
		}
		if _, err := endpoint.conn.WriteToUDP(resp, multicast); err != nil {
			log.Debug("mDNS: announce error", "err", err)
		}
	}
}

// buildResponse constructs an mDNS response for a query that mentions _smb._tcp.
// It is a pure function — no network I/O — so it can be unit-tested directly.
// Returns (responseBytes, matched). matched is false if no question matched.
func buildResponse(query dnsmessage.Message, instance, hostname string, ips []net.IP, port int) ([]byte, bool) {
	instanceFQDN := instance + "._smb._tcp.local."
	hostFQDN := hostname + ".local."

	ptrName := mustNewName(smbService)
	instanceName := mustNewName(instanceFQDN)
	hostName := mustNewName(hostFQDN)

	matched := false
	for _, q := range query.Questions {
		name := strings.ToLower(q.Name.String())
		switch q.Type {
		case dnsmessage.TypePTR:
			if name == strings.ToLower(smbService) {
				matched = true
			}
		case dnsmessage.TypeSRV, dnsmessage.TypeTXT, dnsmessage.TypeALL:
			if name == strings.ToLower(instanceFQDN) {
				matched = true
			}
		case dnsmessage.TypeA:
			if name == strings.ToLower(hostFQDN) {
				matched = true
			}
		}
	}
	if !matched {
		return nil, false
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            query.Header.ID,
		Response:      true,
		Authoritative: true,
		OpCode:        0,
	})
	b.EnableCompression()

	// Always include all records in the answer section for a PTR query.
	// For SRV/TXT/A queries we still include PTR + full set so caches warm up.
	b.StartAnswers()

	// PTR record: _smb._tcp.local. → <instance>._smb._tcp.local.
	b.PTRResource(
		dnsmessage.ResourceHeader{
			Name:  ptrName,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTL,
		},
		dnsmessage.PTRResource{PTR: instanceName},
	)

	// SRV record: <instance>._smb._tcp.local. → <hostname>.local.:port
	b.SRVResource(
		dnsmessage.ResourceHeader{
			Name:  instanceName,
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTL,
		},
		dnsmessage.SRVResource{
			Priority: 0,
			Weight:   0,
			Port:     uint16(port),
			Target:   hostName,
		},
	)

	// TXT record: single empty string (valid per RFC 6763 §6.1).
	b.TXTResource(
		dnsmessage.ResourceHeader{
			Name:  instanceName,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTL,
		},
		dnsmessage.TXTResource{TXT: []string{""}},
	)

	// A records for the host.
	b.StartAdditionals()
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		var addr [4]byte
		copy(addr[:], ip4)
		b.AResource(
			dnsmessage.ResourceHeader{
				Name:  hostName,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   mdnsTTL,
			},
			dnsmessage.AResource{A: addr},
		)
	}

	msg, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return msg, true
}

type multicastIface struct {
	iface net.Interface
	ips   []net.IP
}

// multicastIfaces returns usable multicast interfaces and their own IPv4
// addresses. Loopback is excluded by interface flags, not merely by checking
// whether an address itself is in 127.0.0.0/8; aliases such as 10.10.10.1 on
// lo0 must never be advertised to peers on another network.
func multicastIfaces() ([]multicastIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []multicastIface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		ips := interfaceIPv4s(iface, addrs)
		if len(ips) != 0 {
			out = append(out, multicastIface{iface: iface, ips: ips})
		}
	}
	return out, nil
}

// interfaceIPv4s filters an interface's address list for advertisable IPv4
// addresses. Taking the interface as an argument makes the loopback-interface
// rule explicit and independently testable.
func interfaceIPv4s(iface net.Interface, addrs []net.Addr) []net.IP {
	if iface.Flags&net.FlagLoopback != 0 {
		return nil
	}
	var ips []net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
			continue
		}
		ips = append(ips, append(net.IP(nil), ip4...))
	}
	return ips
}

func mustNewName(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		panic("invalid DNS name: " + s + ": " + err.Error())
	}
	return n
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// errNoMulticast is returned when no multicast-capable interface is found.
type noMulticastError struct{}

func (e *noMulticastError) Error() string { return "no multicast-capable interface available" }

var errNoMulticast = &noMulticastError{}
