package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPorts(t *testing.T) {
	p, err := parsePorts("443,80,80,20-22")
	if err != nil || !reflect.DeepEqual(p, []int{20, 21, 22, 80, 443}) {
		t.Fatalf("%v %v", p, err)
	}
	for _, s := range []string{"", "0", "65536", "5-2", "1-2-3"} {
		if _, err := parsePorts(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestScope(t *testing.T) {
	allow, _ := parseNetworks("127.0.0.0/30")
	exclude, _ := parseNetworks("127.0.0.2")
	ips, err := resolveTargets(context.Background(), "127.0.0.0/30", allow, exclude, 4)
	if err != nil || len(ips) != 3 {
		t.Fatalf("%v %v", ips, err)
	}
	if _, err := resolveTargets(context.Background(), "192.0.2.1", allow, nil, 4); err == nil {
		t.Fatal("accepted unauthorized destination")
	}
	if _, err := resolveTargets(context.Background(), "127.0.0.0/8", allow, nil, 4); err == nil {
		t.Fatal("accepted oversized CIDR")
	}
}

func TestLocalProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if r := probe(context.Background(), "127.0.0.1", port, time.Second); r.Status != "open" {
		t.Fatal(r)
	}
	l.Close()
	if r := probe(context.Background(), "127.0.0.1", port, time.Second); r.Status == "open" {
		t.Fatal(r)
	}
}

func TestCheckpointReplacement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s := checkpoint{Version: 1}
	if err := saveState(p, s); err != nil {
		t.Fatal(err)
	}
	s.Version = 2
	if err := saveState(p, s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		t.Fatalf("%s %v", data, err)
	}
}

func TestIPv6AndExclusions(t *testing.T) {
	allow, err := parseNetworks("::1,192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := resolveTargets(context.Background(), "::1,::ffff:192.0.2.1,192.0.2.1", allow, nil, 4)
	if err != nil || len(addresses) != 2 {
		t.Fatalf("%v %v", addresses, err)
	}
	if _, err := resolveTargets(context.Background(), "::1", allow, allow, 4); err == nil {
		t.Fatal("empty destination set accepted")
	}
}

func TestCancelledProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := probe(ctx, "127.0.0.1", 1, time.Second); r.Status == "open" {
		t.Fatal(r)
	}
}
