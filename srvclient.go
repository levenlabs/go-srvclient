package srvclient

// At the moment go's dns resolver which is built into the net package doesn't
// properly handle the case of a response being too big. Which leads us to
// having to manually parse /etc/resolv.conf and manually make the SRV requests.

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"net"
	"sort"
)

// sortableSRV implements sort.Interface for []*dns.SRV based on
// the Priority and Weight fields
type sortableSRV []*dns.SRV

func (a sortableSRV) Len() int { return len(a) }
func (a sortableSRV) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a sortableSRV) Less(i, j int) bool {
	if a[i].Priority == a[j].Priority {
		return a[i].Weight > a[j].Weight
	}
	return a[i].Priority < a[j].Priority
}

func init() {
	go dnsConfigLoop()
}

func replaceSRVTarget(r *dns.SRV, extra []dns.RR) *dns.SRV {
	for _, e := range extra {
		if eA, ok := e.(*dns.A); ok && eA.Hdr.Name == r.Target {
			r.Target = eA.A.String()
		} else if eAAAA, ok := e.(*dns.AAAA); ok && eAAAA.Hdr.Name == r.Target {
			r.Target = eAAAA.AAAA.String()
		}
	}
	return r
}

// getCFGServers compiles a list of servers from the dnsConfig
// this is a variable so it can be overwritten in tests
var getCFGServers = func(cfg *dnsConfig) []string {
	res := make([]string, len(cfg.servers))
	for i, s := range cfg.servers {
		_, p, _ := net.SplitHostPort(s)
		if p == "" {
			res[i] = s + ":53"
		} else {
			res[i] = s
		}
	}
	return res
}

func lookupSRV(hostname string, replaceWithIPs bool) ([]*dns.SRV, error) {
	cfg, err := dnsGetConfig()
	if err != nil {
		return nil, err
	}

	c := new(dns.Client)
	c.UDPSize = dns.DefaultMsgSize
	if cfg.timeout > 0 {
		timeout := time.Duration(cfg.timeout) * time.Second
		c.DialTimeout = timeout
		c.ReadTimeout = timeout
		c.WriteTimeout = timeout
	}
	fqdn := dns.Fqdn(hostname)
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeSRV)
	m.SetEdns0(dns.DefaultMsgSize, false)

	var res *dns.Msg
	servers := getCFGServers(cfg)
	for _, server := range servers {
		if res, _, err = c.Exchange(m, server); err != nil {
			continue
		}
		if res.Rcode != dns.RcodeFormatError {
			break
		}

		// At this point we got a response, but it was just to tell us that
		// edns0 isn't supported, so we try again without it
		m2 := new(dns.Msg)
		m2.SetQuestion(fqdn, dns.TypeSRV)
		if res, _, err = c.Exchange(m2, server); err == nil {
			break
		}
	}
	if res == nil {
		return nil, errors.New("no available nameservers")
	}

	ans := make([]*dns.SRV, 0, len(res.Answer))
	for i := range res.Answer {
		if ansSRV, ok := res.Answer[i].(*dns.SRV); ok {
			if replaceWithIPs {
				// attempt to replace SRV's Target with the actual IP
				ansSRV = replaceSRVTarget(ansSRV, res.Extra)
			}
			ans = append(ans, ansSRV)
		}
	}
	if len(res.Answer) == 0 {
		return nil, fmt.Errorf("No SRV records for %q", hostname)
	}
	return ans, nil
}

// SRV will perform a SRV request on the given hostname, and then choose one of
// the returned entries randomly based on the priority and weight fields it
// sees. It will return the address ("host:port") of the winning entry, or an
// error if the query couldn't be made or it returned no entries. If the DNS
// server provided the A records for the hosts, then the result will have the
// target replaced with its respective IP.
//
// If the given hostname already has a ":port" appended to it, only the ip will
// be looked up from the SRV request, but the port given will be returned
func SRV(hostname string) (string, error) {

	var portStr string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		portStr = parts[1]
	}

	ans, err := lookupSRV(hostname, true)
	if err != nil {
		return "", err
	}

	srv := pickSRV(ans)

	// Only use the returned port if one wasn't supplied in the hostname
	if portStr == "" {
		portStr = strconv.Itoa(int(srv.Port))
	}

	addr := srv.Target + ":" + portStr
	return addr, nil
}

// SRVNoPort behaves the same as SRV, but the returned address string will not
// contain the port
func SRVNoPort(hostname string) (string, error) {
	addr, err := SRV(hostname)
	if err != nil {
		return "", err
	}

	return addr[:strings.Index(addr, ":")], nil
}

// AllSRV returns the list of all hostnames and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
// AllSRV will NOT replace hostnames with their respective IPs
func AllSRV(hostname string) ([]string, error) {
	var ogPort string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		ogPort = parts[1]
	}

	ans, err := lookupSRV(hostname, false)
	if err != nil {
		return nil, err
	}

	sort.Sort(sortableSRV(ans))

	res := make([]string, len(ans))
	for i := range ans {
		if ogPort != "" {
			res[i] = ans[i].Target + ":" + ogPort
		} else {
			res[i] = ans[i].Target + ":" + strconv.Itoa(int(ans[i].Port))
		}
	}
	return res, nil
}

// MaybeSRV attempts a SRV lookup if the host doesn't contain a port and if the
// SRV lookup succeeds it'll rewrite the host and return it with the lookup
// result. If it fails it'll just return the host originally sent
func MaybeSRV(host string) string {
	if _, p, _ := net.SplitHostPort(host); p == "" {
		if addr, err := SRV(host); err == nil {
			host = addr
		}
	}
	return host
}

func pickSRV(srvs []*dns.SRV) *dns.SRV {
	randSrc := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(randSrc)

	lowPrio := srvs[0].Priority
	picks := make([]*dns.SRV, 0, len(srvs))
	weights := make([]int, 0, len(srvs))

	for i := range srvs {
		if srvs[i].Priority < lowPrio {
			picks = picks[:0]
			weights = weights[:0]
			lowPrio = srvs[i].Priority
		}

		if srvs[i].Priority == lowPrio {
			picks = append(picks, srvs[i])
			weights = append(weights, int(srvs[i].Weight))
		}
	}

	sum := 0
	for i := range weights {
		sum += weights[i]
	}

	r := rand.Intn(sum)
	for i := range weights {
		r -= weights[i]
		if r < 0 {
			return picks[i]
		}
	}

	// We should never get here, just return the first pick
	return picks[0]
}
