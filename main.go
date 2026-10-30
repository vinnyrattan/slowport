// Slowport is a transparent, rate-limited TCP connect scanner.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type result struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Time    string `json:"time"`
}
type checkpoint struct {
	Version   int      `json:"version"`
	Addresses []string `json:"addresses"`
	Ports     []int    `json:"ports"`
	Results   []result `json:"results"`
}

func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		lo, err := strconv.Atoi(bounds[0])
		if err != nil || lo < 1 || lo > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = strconv.Atoi(bounds[1])
			if err != nil || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for p := lo; p <= hi; p++ {
			seen[p] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func parseNetworks(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if ip, err := netip.ParseAddr(token); err == nil {
			ip = ip.Unmap()
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q", token)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("use ordinary IPv4 CIDR notation: %q", token)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveTargets(ctx context.Context, targets string, allowed, excluded []netip.Prefix, max int) ([]string, error) {
	seen := map[netip.Addr]bool{}
	add := func(ip netip.Addr) error {
		ip = ip.Unmap()
		if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("unsupported destination %s", ip)
		}
		if !contains(allowed, ip) {
			return fmt.Errorf("destination %s is outside --allow", ip)
		}
		if !contains(excluded, ip) {
			seen[ip] = true
		}
		if len(seen) > max {
			return fmt.Errorf("target count exceeds --max-targets (%d)", max)
		}
		return nil
	}
	for _, token := range strings.Split(targets, ",") {
		token = strings.TrimSpace(token)
		if p, err := netip.ParsePrefix(token); err == nil {
			if p.Addr().Is4In6() {
				return nil, errors.New("use ordinary IPv4 CIDR notation")
			}
			p = p.Masked()
			// Bound expansion before iterating, including excluded addresses.
			bits := p.Addr().BitLen() - p.Bits()
			if bits >= 63 || uint64(1)<<uint(bits) > uint64(max) {
				return nil, fmt.Errorf("CIDR %s exceeds --max-targets", p)
			}
			for ip := p.Addr(); p.Contains(ip); ip = ip.Next() {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		} else if ip, err := netip.ParseAddr(token); err == nil {
			if err := add(ip); err != nil {
				return nil, err
			}
		} else {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", token)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", token, err)
			}
			for _, ip := range ips {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		}
	}
	addresses := make([]string, 0, len(seen))
	for ip := range seen {
		addresses = append(addresses, ip.String())
	}
	sort.Strings(addresses)
	if len(addresses) == 0 {
		return nil, errors.New("no targets remain after exclusions")
	}
	return addresses, nil
}

func probe(ctx context.Context, address string, port int, timeout time.Duration) result {
	r := result{Address: address, Port: port, Time: time.Now().UTC().Format(time.RFC3339Nano)}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err == nil {
		c.Close()
		r.Status = "open"
		return r
	}
	r.Status = "error"
	r.Detail = err.Error()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		r.Status = "timeout"
	}
	return r
}

func saveState(path string, state checkpoint) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Same-directory staging avoids cross-volume rename and leaves the prior checkpoint intact on write failure.
	f, err := os.CreateTemp(filepath.Dir(path), ".slowport-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeCSV(path string, results []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	err = w.Write([]string{"address", "port", "status", "detail", "time"})
	for _, r := range results {
		if err != nil {
			break
		}
		err = w.Write([]string{r.Address, strconv.Itoa(r.Port), r.Status, r.Detail, r.Time})
	}
	w.Flush()
	if err == nil {
		err = w.Error()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	return errA == nil && errB == nil && strings.EqualFold(aa, bb)
}

func run() error {
	targets := flag.String("targets", "", "Comma-separated IPs, hostnames, or CIDRs")
	allow := flag.String("allow", "", "Required authorized IPs/CIDRs, comma-separated")
	exclude := flag.String("exclude", "", "Excluded IPs/CIDRs, comma-separated")
	portSpec := flag.String("ports", "22,80,443", "TCP ports or inclusive ranges")
	interval := flag.Duration("interval", 5*time.Second, "Minimum delay after each completed connection attempt")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout")
	max := flag.Int("max-targets", 256, "Maximum destination count / CIDR expansion")
	statePath := flag.String("state", "slowport-state.json", "JSON checkpoint and results file")
	csvPath := flag.String("csv", "slowport-results.csv", "CSV output written on completion or Ctrl+C")
	resume := flag.Bool("resume", false, "Resume matching checkpoint; targets and ports must match")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; use --help")
	}
	if *targets == "" || *allow == "" {
		return errors.New("--targets and --allow are required; scan only systems you are authorized to assess")
	}
	if *interval < time.Second || *timeout <= 0 || *max < 1 {
		return errors.New("interval must be at least 1s; timeout and max-targets must be positive")
	}
	if samePath(*statePath, *csvPath) {
		return errors.New("state and CSV paths must differ")
	}
	ports, err := parsePorts(*portSpec)
	if err != nil {
		return err
	}
	allowed, err := parseNetworks(*allow)
	if err != nil {
		return err
	}
	excluded, err := parseNetworks(*exclude)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dnsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	addresses, err := resolveTargets(dnsCtx, *targets, allowed, excluded, *max)
	if err != nil {
		return err
	}
	state := checkpoint{Version: 1, Addresses: addresses, Ports: ports, Results: []result{}}
	if *resume {
		data, err := os.ReadFile(*statePath)
		if err != nil {
			return err
		}
		var saved checkpoint
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		if saved.Version != 1 || !reflect.DeepEqual(saved.Addresses, addresses) || !reflect.DeepEqual(saved.Ports, ports) {
			return errors.New("checkpoint targets/ports do not match; use the original scope or a new state file")
		}
		state = saved
	} else if _, err := os.Stat(*statePath); err == nil {
		return errors.New("state file already exists; use --resume or a different --state")
	} else if !os.IsNotExist(err) {
		return err
	}
	done := map[string]bool{}
	for _, r := range state.Results {
		done[net.JoinHostPort(r.Address, strconv.Itoa(r.Port))] = true
	}
	if err := saveState(*statePath, state); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Scanning %d destinations, %d ports each; sequential TCP connects, delay %s. Ctrl+C saves progress.\n", len(addresses), len(ports), *interval)
	// Always wait before the first probe, including after a resume.
	for _, address := range addresses {
		for _, port := range ports {
			if done[net.JoinHostPort(address, strconv.Itoa(port))] {
				continue
			}
			timer := time.NewTimer(*interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return writeCSV(*csvPath, state.Results)
			case <-timer.C:
			}
			r := probe(ctx, address, port, *timeout)
			if ctx.Err() != nil {
				return writeCSV(*csvPath, state.Results)
			}
			state.Results = append(state.Results, r)
			if err := saveState(*statePath, state); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s %s:%d %s\n", r.Time, r.Address, r.Port, r.Status)
		}
	}
	if err := writeCSV(*csvPath, state.Results); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Complete: %d results. JSON: %s CSV: %s\n", len(state.Results), *statePath, *csvPath)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "slowport:", err)
		os.Exit(1)
	}
}
