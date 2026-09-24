package discovery

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestBuildResponse_PTRQuery verifies deterministic response building without sockets.
func TestBuildResponse_PTRQuery(t *testing.T) {
	instance := "gosamba"
	hostname := "myserver"
	port := 445
	ips := []net.IP{net.ParseIP("192.168.1.10").To4()}

	// Build a PTR query for _smb._tcp.local.
	query := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       0,
			Response: false,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  mustName(t, "_smb._tcp.local."),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	buf, matched := buildResponse(query, instance, hostname, ips, port)
	if !matched {
		t.Fatal("expected matched=true for _smb._tcp.local. PTR query")
	}
	if len(buf) == 0 {
		t.Fatal("expected non-empty response bytes")
	}

	// Parse the response back.
	var resp dnsmessage.Message
	if err := resp.Unpack(buf); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}
	if !resp.Header.Response {
		t.Error("response header should have Response=true")
	}

	// M1: Authoritative bit must be set.
	if !resp.Header.Authoritative {
		t.Error("response header should have Authoritative=true")
	}

	var gotPTR bool
	var gotSRV bool
	var gotTXT bool
	var gotA bool
	var srvPort uint16
	var srvTarget string
	var srvPriority, srvWeight uint16

	for _, ans := range resp.Answers {
		switch ans.Header.Type {
		case dnsmessage.TypePTR:
			r := ans.Body.(*dnsmessage.PTRResource)
			want := instance + "._smb._tcp.local."
			if r.PTR.String() != want {
				t.Errorf("PTR target: got %q, want %q", r.PTR.String(), want)
			}
			gotPTR = true

		case dnsmessage.TypeSRV:
			r := ans.Body.(*dnsmessage.SRVResource)
			srvPort = r.Port
			srvTarget = r.Target.String()
			srvPriority = r.Priority
			srvWeight = r.Weight
			gotSRV = true

		case dnsmessage.TypeTXT:
			r := ans.Body.(*dnsmessage.TXTResource)
			// M2: TXT must have exactly one zero-length string (RFC 6763 valid-empty-TXT).
			if len(r.TXT) != 1 || r.TXT[0] != "" {
				t.Errorf("TXT record: got %v, want [\"\"]", r.TXT)
			}
			gotTXT = true

		case dnsmessage.TypeA:
			r := ans.Body.(*dnsmessage.AResource)
			gotA = true
			_ = r
		}
	}

	// Also check additional records for SRV/A/TXT if not in answers.
	for _, add := range resp.Additionals {
		switch add.Header.Type {
		case dnsmessage.TypeSRV:
			r := add.Body.(*dnsmessage.SRVResource)
			srvPort = r.Port
			srvTarget = r.Target.String()
			srvPriority = r.Priority
			srvWeight = r.Weight
			gotSRV = true
		case dnsmessage.TypeTXT:
			r := add.Body.(*dnsmessage.TXTResource)
			if len(r.TXT) != 1 || r.TXT[0] != "" {
				t.Errorf("TXT record (additional): got %v, want [\"\"]", r.TXT)
			}
			gotTXT = true
		case dnsmessage.TypeA:
			gotA = true
		}
	}

	if !gotPTR {
		t.Error("response missing PTR record")
	}
	if !gotSRV {
		t.Error("response missing SRV record")
	} else {
		if int(srvPort) != port {
			t.Errorf("SRV port: got %d, want %d", srvPort, port)
		}
		wantTarget := hostname + ".local."
		if srvTarget != wantTarget {
			t.Errorf("SRV target: got %q, want %q", srvTarget, wantTarget)
		}
		// M3: SRV priority and weight must both be 0.
		if srvPriority != 0 {
			t.Errorf("SRV priority: got %d, want 0", srvPriority)
		}
		if srvWeight != 0 {
			t.Errorf("SRV weight: got %d, want 0", srvWeight)
		}
	}
	if !gotTXT {
		t.Error("response missing TXT record")
	}
	if !gotA {
		t.Error("response missing A record")
	}
}

func TestInterfaceIPv4s_RejectsLoopbackInterfaceAliases(t *testing.T) {
	iface := net.Interface{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback | net.FlagMulticast}
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("10.10.10.1"), Mask: net.CIDRMask(24, 32)},
	}
	if got := interfaceIPv4s(iface, addrs); len(got) != 0 {
		t.Fatalf("loopback interface addresses = %v, want none", got)
	}
}

func TestInterfaceConnResponsesUseOnlyOwnAddresses(t *testing.T) {
	query := dnsmessage.Message{
		Questions: []dnsmessage.Question{{
			Name:  mustName(t, smbService),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}},
	}
	endpoints := []interfaceConn{
		{ips: []net.IP{net.ParseIP("172.30.1.86")}},
		{ips: []net.IP{net.ParseIP("192.168.1.20")}},
	}
	wants := [][]string{{"172.30.1.86"}, {"192.168.1.20"}}

	for i, endpoint := range endpoints {
		buf, matched := endpoint.buildResponse(query, "gosamba", "myserver", 445)
		if !matched {
			t.Fatalf("interface %d response did not match", i)
		}
		var response dnsmessage.Message
		if err := response.Unpack(buf); err != nil {
			t.Fatalf("interface %d response: %v", i, err)
		}
		var got []string
		for _, record := range response.Additionals {
			if a, ok := record.Body.(*dnsmessage.AResource); ok {
				got = append(got, net.IP(a.A[:]).String())
			}
		}
		if !reflect.DeepEqual(got, wants[i]) {
			t.Fatalf("interface %d A records = %v, want %v", i, got, wants[i])
		}
	}
}

// TestBuildResponse_UnrelatedQuery asserts no match for unrelated service queries.
func TestBuildResponse_UnrelatedQuery(t *testing.T) {
	instance := "gosamba"
	hostname := "myserver"
	port := 445
	ips := []net.IP{net.ParseIP("192.168.1.10").To4()}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustName(t, "_http._tcp.local."),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	_, matched := buildResponse(query, instance, hostname, ips, port)
	if matched {
		t.Error("expected matched=false for unrelated service query _http._tcp.local.")
	}
}

// TestBuildResponse_SRVQuery tests a direct SRV query for the instance.
func TestBuildResponse_SRVQuery(t *testing.T) {
	instance := "gosamba"
	hostname := "myserver"
	port := 445
	ips := []net.IP{net.ParseIP("10.0.0.1").To4()}

	query := dnsmessage.Message{
		Header: dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustName(t, instance+"._smb._tcp.local."),
				Type:  dnsmessage.TypeSRV,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	buf, matched := buildResponse(query, instance, hostname, ips, port)
	if !matched {
		t.Fatal("expected matched=true for SRV query on instance")
	}
	if len(buf) == 0 {
		t.Fatal("expected non-empty response")
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf); err != nil {
		t.Fatalf("failed to unpack: %v", err)
	}

	var gotSRV bool
	for _, ans := range resp.Answers {
		if ans.Header.Type == dnsmessage.TypeSRV {
			r := ans.Body.(*dnsmessage.SRVResource)
			if int(r.Port) != port {
				t.Errorf("SRV port: got %d, want %d", r.Port, port)
			}
			gotSRV = true
		}
	}
	if !gotSRV {
		t.Error("SRV response missing SRV record in answers")
	}
}

// TestAdvertise_LiveRoundTrip attempts a real multicast exchange.
// Skips gracefully if multicast is unavailable (containers, CI).
func TestAdvertise_LiveRoundTrip(t *testing.T) {
	// Try to find a multicast-capable interface. Skip if none.
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	var hasMulticast bool
	for _, iface := range ifaces {
		if iface.Flags&net.FlagMulticast != 0 && iface.Flags&net.FlagUp != 0 {
			hasMulticast = true
			break
		}
	}
	if !hasMulticast {
		t.Skip("no multicast-capable interface available; skipping live mDNS test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	instance := "gosamba-test"
	hostname := "testhost"
	port := 44500

	closer, err := Advertise(ctx, instance, hostname, port, nil)
	if err != nil {
		t.Skipf("Advertise failed (likely no multicast in this environment): %v", err)
	}
	defer closer.Close()

	// Give the responder a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Send a PTR query to the mDNS multicast group.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	})
	if err != nil {
		t.Skipf("cannot dial mDNS multicast address: %v", err)
	}
	defer conn.Close()

	q := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1234, Response: false, RecursionDesired: false},
		Questions: []dnsmessage.Question{
			{
				Name:  mustName(t, "_smb._tcp.local."),
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	qbuf, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	if _, err := conn.Write(qbuf); err != nil {
		t.Skipf("cannot write to mDNS multicast: %v", err)
	}

	// Listen on multicast for the response (with short deadline).
	lconn, err := net.ListenMulticastUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	})
	if err != nil {
		t.Skipf("cannot join mDNS multicast group for receive: %v", err)
	}
	defer lconn.Close()
	lconn.SetReadDeadline(time.Now().Add(2 * time.Second))

	rbuf := make([]byte, 4096)
	found := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := lconn.ReadFromUDP(rbuf)
		if err != nil {
			break
		}
		var resp dnsmessage.Message
		if err := resp.Unpack(rbuf[:n]); err != nil {
			continue
		}
		if !resp.Header.Response {
			continue
		}
		for _, ans := range resp.Answers {
			if ans.Header.Type == dnsmessage.TypePTR {
				r := ans.Body.(*dnsmessage.PTRResource)
				if r.PTR.String() == instance+"._smb._tcp.local." {
					found = true
				}
			}
		}
		if found {
			break
		}
	}

	if !found {
		t.Logf("live mDNS round-trip: no matching response seen within deadline (may be multicast routing issue in this env)")
		// Non-fatal: multicast may be blocked in this environment.
		// The deterministic unit tests are the required proof.
		t.Skip("live mDNS round-trip did not observe response; skipping (not a build failure)")
	}
}

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("invalid DNS name %q: %v", s, err)
	}
	return n
}
