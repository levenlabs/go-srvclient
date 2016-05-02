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
	"sync"
	"time"

	"net"
	"sort"

	"github.com/miekg/dns"
)

// sortableSRV implements sort.Interface for []*dns.SRV based on
// the Priority and Weight fields
type sortableSRV []*dns.SRV

func (a sortableSRV) Len() int      { return len(a) }
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

// SRVClient is a holder for methods related to SRV lookups
type SRVClient struct {
	cacheLast  map[string]*dns.Msg
	cacheLastL sync.RWMutex

	// A list of addresses ("ip:port") which should be used as the resolver
	// list. If none are set then the resolver settings in /etc/resolv.conf are
	// used
	ResolverAddrs []string

	// If non-nill, will be called on messages returned from dns servers prior
	// to them being processed (i.e. before they are cached, sorted,
	// ip-replaced, etc...)
	Preprocess func(*dns.Msg)
}

// EnableCacheLast is used to make SRVClient cache the last successful SRV
// response for each domain requested, and if the next request results in some
// kind of error it will use that last response instead.
func (sc *SRVClient) EnableCacheLast() {
	sc.cacheLastL.Lock()
	if sc.cacheLast == nil {
		sc.cacheLast = map[string]*dns.Msg{}
	}
	sc.cacheLastL.Unlock()
}

// DefaultSRVClient is an instance of SRVClient with all zero'd values, used as
// the default client for all global methods. It can be overwritten prior to any
// of the methods being used in order to modify their behavior
var DefaultSRVClient SRVClient

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

func (sc *SRVClient) doCacheLast(hostname string, res *dns.Msg) *dns.Msg {
	if sc.cacheLast == nil {
		return res
	}

	if res == nil || len(res.Answer) == 0 {
		sc.cacheLastL.RLock()
		defer sc.cacheLastL.RUnlock()
		return sc.cacheLast[hostname]
	}

	sc.cacheLastL.Lock()
	defer sc.cacheLastL.Unlock()
	sc.cacheLast[hostname] = res
	return res
}

func (sc *SRVClient) clientConfig() (*dns.Client, dnsConfig, error) {
	cfg, err := dnsGetConfig()
	if err != nil {
		return nil, cfg, err
	}
	if len(sc.ResolverAddrs) > 0 {
		cfg.servers = sc.ResolverAddrs
	}

	c := new(dns.Client)
	c.UDPSize = dns.DefaultMsgSize
	if cfg.timeout > 0 {
		timeout := time.Duration(cfg.timeout) * time.Second
		c.DialTimeout = timeout
		c.ReadTimeout = timeout
		c.WriteTimeout = timeout
	}
	return c, cfg, nil
}

func (sc *SRVClient) doExchange(c *dns.Client, fqdn, server string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeSRV)
	m.SetEdns0(dns.DefaultMsgSize, false)

	if res, _, err := c.Exchange(m, server); err != nil {
		return nil
	} else if res.Rcode != dns.RcodeFormatError {
		return res
	}

	// At this point we got a response, but it was just to tell us that
	// edns0 isn't supported, so we try again without it
	m2 := new(dns.Msg)
	m2.SetQuestion(fqdn, dns.TypeSRV)
	if res, _, err := c.Exchange(m2, server); err == nil {
		return res
	}
	return nil
}

func answersFromMsg(m *dns.Msg, replaceWithIPs bool) []*dns.SRV {
	ans := make([]*dns.SRV, 0, len(m.Answer))
	for i := range m.Answer {
		if ansSRV, ok := m.Answer[i].(*dns.SRV); ok {
			if replaceWithIPs {
				// attempt to replace SRV's Target with the actual IP
				ansSRV = replaceSRVTarget(ansSRV, m.Extra)
			}
			ans = append(ans, ansSRV)
		}
	}
	return ans
}

func (sc *SRVClient) lookupSRV(hostname string, replaceWithIPs bool) ([]*dns.SRV, error) {
	c, cfg, err := sc.clientConfig()
	if err != nil {
		return nil, err
	}

	fqdn := dns.Fqdn(hostname)
	var res *dns.Msg
	for _, server := range cfg.servers {
		if res = sc.doExchange(c, fqdn, server); res != nil {
			break
		}
	}

	if sc.Preprocess != nil && res != nil {
		sc.Preprocess(res)
	}

	// Handles caching this response if it's a successful one, or replacing res
	// with the last response if not. Does nothing if sc.cacheLast is false.
	res = sc.doCacheLast(hostname, res)

	if res == nil {
		return nil, errors.New("no available nameservers")
	}

	ans := answersFromMsg(res, replaceWithIPs)
	if len(ans) == 0 {
		return nil, fmt.Errorf("No SRV records for %q", hostname)
	}

	return ans, nil
}

func srvToStr(srv *dns.SRV, port string) string {
	if port == "" {
		port = strconv.Itoa(int(srv.Port))
	}
	return net.JoinHostPort(srv.Target, port)
}

// SRV calls the SRV method on the DefaultSRVClient
func SRV(hostname string) (string, error) {
	return DefaultSRVClient.SRV(hostname)
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
func (sc *SRVClient) SRV(hostname string) (string, error) {
	var portStr string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		portStr = parts[1]
	}

	ans, err := sc.lookupSRV(hostname, true)
	if err != nil {
		return "", err
	}

	srv := pickSRV(ans)

	return srvToStr(srv, portStr), nil
}

// SRVNoPort calls the SRVNoPort method on the DefaultSRVClient
func SRVNoPort(hostname string) (string, error) {
	return DefaultSRVClient.SRVNoPort(hostname)
}

// SRVNoPort behaves the same as SRV, but the returned address string will not
// contain the port
func (sc *SRVClient) SRVNoPort(hostname string) (string, error) {
	addr, err := SRV(hostname)
	if err != nil {
		return "", err
	}

	host, _, err := net.SplitHostPort(addr)
	return host, err
}

// AllSRV calls the AllSRV method on the DefaultSRVClient
func AllSRV(hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRV(hostname)
}

// AllSRV returns the list of all hostnames and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
// AllSRV will NOT replace hostnames with their respective IPs
func (sc *SRVClient) AllSRV(hostname string) ([]string, error) {
	var ogPort string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		ogPort = parts[1]
	}

	ans, err := sc.lookupSRV(hostname, false)
	if err != nil {
		return nil, err
	}

	sort.Sort(sortableSRV(ans))

	res := make([]string, len(ans))
	for i := range ans {
		res[i] = srvToStr(ans[i], ogPort)
	}
	return res, nil
}

// MaybeSRV calls the MaybeSRV method on the DefaultSRVClient
func MaybeSRV(host string) string {
	return DefaultSRVClient.MaybeSRV(host)
}

// MaybeSRV attempts a SRV lookup if the host doesn't contain a port and if the
// SRV lookup succeeds it'll rewrite the host and return it with the lookup
// result. If it fails it'll just return the host originally sent
func (sc *SRVClient) MaybeSRV(host string) string {
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

	if sum == 0 {
		return picks[rand.Intn(len(picks))]
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

// MaybeSRVURL calls the MaybeSRVURL method on the DefaultSRVClient
func MaybeSRVURL(host string) string {
	return DefaultSRVClient.MaybeSRVURL(host)
}

// MaybeSRVURL calls MaybeSRV and also prepends http://if no scheme was sent
func (sc *SRVClient) MaybeSRVURL(host string) string {
	host = sc.MaybeSRV(host)
	if !strings.Contains(host, "://") {
		return "http://" + host
	}
	return host
}
