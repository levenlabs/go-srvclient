package srvclient

// At the moment go's dns resolver which is built into the net package doesn't
// properly handle the case of a response being too big. Which leads us to
// having to manually parse /etc/resolv.conf and manually make the SRV requests.

import (
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"net"
	"sort"

	"github.com/miekg/dns"
)

func init() {
	go dnsConfigLoop()
}

// SRVClient is a holder for methods related to SRV lookups. Use new(SRVClient)
// to initialize one.
type SRVClient struct {
	cacheLast  map[string]*dns.Msg
	cacheLastL sync.RWMutex

	client        *dns.Client
	tcpClient     *dns.Client
	lastConfig    clientConfig
	clientConfigL sync.RWMutex
	UDPSize       uint16

	// If IgnoreTruncated is true, then lookups will NOT fallback to TCP when
	// they were truncated over UDP.
	IgnoreTruncated bool

	// A list of addresses ("ip:port") which should be used as the resolver
	// list. If none are set then the resolver settings in /etc/resolv.conf are
	// used. This can only be updated before the SRVClient is used for the first
	// time.
	ResolverAddrs []string

	// If non-nill, will be called on messages returned from dns servers prior
	// to them being processed (i.e. before they are cached, sorted,
	// ip-replaced, etc...)
	Preprocess func(*dns.Msg)

	numUDPQueries         int64
	numTCPQueries         int64
	numTruncatedResponses int64
	numExchangeErrors     int64
	numCacheLastHits      int64
	numCacheLastMisses    int64
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
var DefaultSRVClient = new(SRVClient)

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
		if cres, ok := sc.cacheLast[hostname]; ok {
			res = cres
			atomic.AddInt64(&sc.numCacheLastHits, 1)
		} else {
			atomic.AddInt64(&sc.numCacheLastMisses, 1)
		}
		return res
	}

	sc.cacheLastL.Lock()
	defer sc.cacheLastL.Unlock()
	sc.cacheLast[hostname] = res
	return res
}

func (sc *SRVClient) newClient(cfg dns.ClientConfig) *dns.Client {
	c := new(dns.Client)
	if sc.UDPSize != 0 {
		c.UDPSize = sc.UDPSize
	} else {
		c.UDPSize = dns.DefaultMsgSize
	}
	c.SingleInflight = true
	if cfg.Timeout > 0 {
		timeout := time.Duration(cfg.Timeout) * time.Second
		c.DialTimeout = timeout
		c.ReadTimeout = timeout
		c.WriteTimeout = timeout
	}
	return c
}

func (sc *SRVClient) clientConfig() (*dns.Client, *dns.Client, dns.ClientConfig, error) {
	cfg, err := dnsGetConfig()
	if err != nil {
		return nil, nil, cfg.ClientConfig, err
	}
	if len(sc.ResolverAddrs) > 0 {
		cfg.Servers = sc.ResolverAddrs
	}

	sc.clientConfigL.RLock()
	shouldUpdate := sc.client == nil || sc.lastConfig.updated.Before(cfg.updated)
	if shouldUpdate {
		sc.clientConfigL.RUnlock()
		sc.clientConfigL.Lock()
		defer sc.clientConfigL.Unlock()
		sc.client = sc.newClient(cfg.ClientConfig)
		tcpClient := sc.newClient(cfg.ClientConfig)
		tcpClient.Net = "tcp"
		sc.tcpClient = tcpClient
		sc.lastConfig = cfg
	} else {
		defer sc.clientConfigL.RUnlock()
	}

	return sc.client, sc.tcpClient, sc.lastConfig.ClientConfig, nil
}

func (sc *SRVClient) doExchange(c *dns.Client, fqdn, server string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeSRV)
	var size uint16
	if c.Net != "tcp" && c.UDPSize != 0 {
		size = c.UDPSize
		m.SetEdns0(c.UDPSize, false)
	}

	res, _, err := c.Exchange(m, server)
	if err != nil {
		return res, err
	}
	if res.Rcode != dns.RcodeFormatError || size == 0 {
		return res, nil
	}

	// At this point we got a response, but it was just to tell us that
	// edns0 isn't supported, so we try again without it
	m2 := new(dns.Msg)
	m2.SetQuestion(fqdn, dns.TypeSRV)
	res, _, err = c.Exchange(m2, server)
	return res, err
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
	c, tcpc, cfg, err := sc.clientConfig()
	if err != nil {
		return nil, err
	}

	fqdn := dns.Fqdn(hostname)
	var res *dns.Msg
	var tres *dns.Msg
	for _, server := range cfg.Servers {
		atomic.AddInt64(&sc.numUDPQueries, 1)
		res, err = sc.doExchange(c, fqdn, server)
		if err != nil || res == nil {
			atomic.AddInt64(&sc.numExchangeErrors, 1)
			continue
		}
		if res.Truncated {
			atomic.AddInt64(&sc.numTruncatedResponses, 1)
			// store truncated in case TCP fails
			tres = res
			// try using TCP now
			if !sc.IgnoreTruncated {
				atomic.AddInt64(&sc.numTCPQueries, 1)
				res, err = sc.doExchange(tcpc, fqdn, server)
				if err != nil || res == nil {
					atomic.AddInt64(&sc.numExchangeErrors, 1)
					continue
				}
			} else {
				continue
			}
		}
		// no error so stop
		break
	}

	if sc.Preprocess != nil {
		// preprocess both since we don't know which one we'll use yet
		if res != nil {
			sc.Preprocess(res)
		}
		if tres != nil {
			sc.Preprocess(tres)
		}
	}

	// Handles caching this response if it's a successful one, or replacing res
	// with the last response if not. Does nothing if sc.cacheLast is false.
	res = sc.doCacheLast(hostname, res)

	// if we got a truncated error from a server but it was a success, use it
	// we check this AFTER the cache in case we have a better one in the cache
	if res != nil && res.Rcode != dns.RcodeSuccess && tres != nil && tres.Rcode == dns.RcodeSuccess {
		res = tres
	}

	if res == nil {
		if err == nil {
			err = errors.New("no available nameservers")
		}
		return nil, err
	}

	ans := answersFromMsg(res, replaceWithIPs)
	if len(ans) == 0 {
		return nil, &ErrNotFound{hostname}
	}

	return ans, err
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

func (sc *SRVClient) srv(hostname string, replaceWithIPs bool) (string, error) {
	var portStr string
	if h, p, _ := net.SplitHostPort(hostname); p != "" && h != "" {
		// check for host being an IP and if so, just return what they sent
		if ip := net.ParseIP(h); ip != nil {
			return hostname, nil
		}
		hostname = h
		portStr = p
	}

	ans, err := sc.lookupSRV(hostname, replaceWithIPs)
	// only return an error here if we also didn't get an answer
	if len(ans) == 0 && err != nil {
		return "", err
	}

	srv := pickSRV(ans)

	return srvToStr(srv, portStr), err
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
//
// If the given hostname is "ip:port", it'll just immediately return what you
// sent.
func (sc *SRVClient) SRV(hostname string) (string, error) {
	return sc.srv(hostname, true)
}

// SRVNoTranslate calls the SRVNoTranslate method on the DefaultSRVClient
func SRVNoTranslate(hostname string) (string, error) {
	return DefaultSRVClient.SRVNoTranslate(hostname)
}

// SRVNoTranslate is exactly like SRV except it won't translate names to their
// respective IPs
func (sc *SRVClient) SRVNoTranslate(hostname string) (string, error) {
	return sc.srv(hostname, false)
}

// SRVNoPort calls the SRVNoPort method on the DefaultSRVClient
func SRVNoPort(hostname string) (string, error) {
	return DefaultSRVClient.SRVNoPort(hostname)
}

// SRVNoPort behaves the same as SRV, but the returned address string will not
// contain the port
func (sc *SRVClient) SRVNoPort(hostname string) (string, error) {
	addr, err := sc.SRV(hostname)
	if err != nil {
		return "", err
	}

	host, _, err := net.SplitHostPort(addr)
	return host, err
}

// SRVStats contains lifetime counts for various statistics
type SRVStats struct {
	UDPQueries         int64
	TCPQueries         int64
	TruncatedResponses int64
	ExchangeErrors     int64
	CacheLastHits      int64
	CacheLastMisses    int64
}

// Stats returns the latest SRVStats struct for the given client
func (sc *SRVClient) Stats() SRVStats {
	return SRVStats{
		UDPQueries:         atomic.LoadInt64(&sc.numUDPQueries),
		TCPQueries:         atomic.LoadInt64(&sc.numTCPQueries),
		TruncatedResponses: atomic.LoadInt64(&sc.numTruncatedResponses),
		ExchangeErrors:     atomic.LoadInt64(&sc.numExchangeErrors),
		CacheLastHits:      atomic.LoadInt64(&sc.numCacheLastHits),
		CacheLastMisses:    atomic.LoadInt64(&sc.numCacheLastMisses),
	}
}

// AllSRV calls the AllSRV method on the DefaultSRVClient
func AllSRV(hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRV(hostname)
}

// AllSRVTranslate calls the AllSRVTranslate method on the DefaultSRVClient
func AllSRVTranslate(hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRVTranslate(hostname)
}

func (sc *SRVClient) allSRV(hostname string, translateIPs bool) ([]string, error) {
	var ogPort string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		ogPort = parts[1]
	}

	ans, err := sc.lookupSRV(hostname, translateIPs)
	// only return an error here if we also didn't get an answer
	if len(ans) == 0 && err != nil {
		return nil, err
	}

	// sort the lowest priority to the front and if priorities match
	// sort the highest weights to the front
	// use a stable sort in case the server's order is meaningful
	sort.SliceStable(ans, func(i, j int) bool {
		if ans[i].Priority == ans[j].Priority {
			return ans[i].Weight > ans[j].Weight
		}
		return ans[i].Priority < ans[j].Priority
	})

	res := make([]string, len(ans))
	for i := range ans {
		res[i] = srvToStr(ans[i], ogPort)
	}
	return res, err
}

// AllSRV returns the list of all hostnames and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
// AllSRV will NOT replace hostnames with their respective IPs
func (sc *SRVClient) AllSRV(hostname string) ([]string, error) {
	return sc.allSRV(hostname, false)
}

// AllSRVTranslate returns the list of all IPs and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
func (sc *SRVClient) AllSRVTranslate(hostname string) ([]string, error) {
	return sc.allSRV(hostname, true)
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
		if addr, err := sc.SRV(host); err == nil {
			host = addr
		}
	}
	return host
}

var (
	randPool = sync.Pool{
		New: func() interface{} {
			return rand.New(rand.NewSource(time.Now().UnixNano()))
		},
	}
)

func pickSRV(srvs []*dns.SRV) *dns.SRV {
	rand := randPool.Get().(*rand.Rand)

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

// MaybeSRVURL calls MaybeSRV and also prepends http:// if no scheme was sent
func (sc *SRVClient) MaybeSRVURL(host string) string {
	host = sc.MaybeSRV(host)
	if !strings.Contains(host, "://") {
		return "http://" + host
	}
	return host
}
