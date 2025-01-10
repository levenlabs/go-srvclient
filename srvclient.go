package srvclient

// At the moment go's dns resolver which is built into the net package doesn't
// properly handle the case of a response being too big. Which leads us to
// having to manually parse /etc/resolv.conf and manually make the SRV requests.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func init() {
	go dnsConfigLoop()
}

type inFlightRes struct {
	msg  *dns.Msg
	err  error
	done chan struct{}
}

// SRVClient is a holder for methods related to SRV lookups. Use new(SRVClient)
// to initialize one.
type SRVClient struct {
	cacheLast     map[string]*dns.Msg
	cacheLastL    sync.RWMutex
	client        *dns.Client
	tcpClient     *dns.Client
	lastConfig    clientConfig
	clientConfigL sync.RWMutex
	inFlights     sync.Map

	// OnExchangeError specifies an optional function to call for exchange errors
	// that otherwise might be ignored if another server did not error.
	OnExchangeError func(ctx context.Context, hostname string, server string, error error)

	// UDPSize specifies the maximum receive buffer for UDP messages
	UDPSize uint16

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

	// SingleInFlight will combine duplicate lookups and only issue a single DNS
	// query, mirroring the response to all callers.
	SingleInFlight bool

	numUDPQueries         int64
	numTCPQueries         int64
	numTruncatedResponses int64
	numExchangeErrors     int64
	numCacheLastHits      int64
	numCacheLastMisses    int64
	numInFlightHits       int64
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
	// we don't use dns's SingleInFlight because of https://github.com/miekg/dns/issues/1449
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

func (sc *SRVClient) doExchange(ctx context.Context, c *dns.Client, fqdn, server string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeSRV)
	var size uint16
	if c.Net != "tcp" && c.UDPSize != 0 {
		size = c.UDPSize
		m.SetEdns0(c.UDPSize, false)
	}

	res, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		if sc.OnExchangeError != nil {
			sc.OnExchangeError(ctx, fqdn, server, err)
		}
		return res, err
	}
	if res.Rcode != dns.RcodeFormatError || size == 0 {
		return res, nil
	}

	// At this point we got a response, but it was just to tell us that
	// edns0 isn't supported, so we try again without it
	m2 := new(dns.Msg)
	m2.SetQuestion(fqdn, dns.TypeSRV)
	res, _, err = c.ExchangeContext(ctx, m2, server)
	if err != nil {
		if sc.OnExchangeError != nil {
			sc.OnExchangeError(ctx, fqdn, server, err)
		}
	}
	return res, err
}

func (sc *SRVClient) innerLookupSRV(ctx context.Context, fqdn string, c, tcpc *dns.Client, cfg dns.ClientConfig, skipCache bool) (*dns.Msg, error) {
	var res *dns.Msg
	var tres *dns.Msg
	var err error
	for _, server := range cfg.Servers {
		atomic.AddInt64(&sc.numUDPQueries, 1)
		res, err = sc.doExchange(ctx, c, fqdn, server)
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
				res, err = sc.doExchange(ctx, tcpc, fqdn, server)
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

	if !skipCache {
		// Handles caching this response if it's a successful one, or replacing res
		// with the last response if not. Does nothing if sc.cacheLast is false.
		res = sc.doCacheLast(fqdn, res)
	}

	// if we got a truncated error from a server but it was a success, use it
	// we check this AFTER the cache in case we have a better one in the cache
	if res != nil && res.Rcode != dns.RcodeSuccess && tres != nil && tres.Rcode == dns.RcodeSuccess {
		res = tres
		if !skipCache {
			// cache tres instead
			res = sc.doCacheLast(fqdn, tres)
		}
	}

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

func cacheKey(fqdn string, cfg dns.ClientConfig) string {
	return fmt.Sprintf("%s:%v", fqdn, cfg.Servers)
}

func (sc *SRVClient) lookupSRV(ctx context.Context, hostname string, replaceWithIPs bool, skipCache bool) ([]*dns.SRV, error) {
	c, tcpc, cfg, err := sc.clientConfig()
	if err != nil {
		return nil, err
	}

	fqdn := dns.Fqdn(hostname)

	var msg *dns.Msg
	if sc.SingleInFlight {
		var res *inFlightRes
		key := cacheKey(fqdn, cfg)
		resi, loaded := sc.inFlights.Load(key)
		if loaded {
			res = resi.(*inFlightRes)
		} else {
			res = &inFlightRes{
				done: make(chan struct{}),
			}
			resi, loaded = sc.inFlights.LoadOrStore(key, res)
			if loaded {
				res = resi.(*inFlightRes)
			}
		}
		// if it wasn't loaded then we just stored the res and we should kick off the
		// query
		if !loaded {
			do := func(ctx context.Context) {
				defer close(res.done)
				defer sc.inFlights.Delete(key)
				res.msg, res.err = sc.innerLookupSRV(ctx, fqdn, c, tcpc, cfg, skipCache)
			}
			// check for an empty context and we don't need to make a goroutine since
			// we can rely on the context not being cancelled
			if _, ok := ctx.Deadline(); !ok && ctx.Done() == nil {
				do(ctx)
			} else {
				// otherwise we need to ignore cancellation and do it in a goroutine so
				// that the outer request can respect the context
				go do(withoutCancel{ctx})
			}
		} else {
			atomic.AddInt64(&sc.numInFlightHits, 1)
		}
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-res.done:
			msg = res.msg.Copy()
			err = res.err
		}
	} else {
		msg, err = sc.innerLookupSRV(ctx, fqdn, c, tcpc, cfg, skipCache)
	}

	if msg == nil {
		if err == nil {
			err = errors.New("no available nameservers")
		}
		return nil, err
	}

	ans := answersFromMsg(msg, replaceWithIPs)
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

func (sc *SRVClient) srv(ctx context.Context, hostname string, replaceWithIPs bool, skipCache bool) (string, error) {
	var portStr string
	if h, p, _ := net.SplitHostPort(hostname); p != "" && h != "" {
		// check for host being an IP and if so, just return what they sent
		if ip := net.ParseIP(h); ip != nil {
			return hostname, nil
		}
		hostname = h
		portStr = p
	}

	ans, err := sc.lookupSRV(ctx, hostname, replaceWithIPs, skipCache)
	// only return an error here if we also didn't get an answer
	if len(ans) == 0 && err != nil {
		return "", err
	}

	// lookupSRV returns &ErrNotFound{hostname} if ans is empty so we MUST have at
	// least 1 record here
	srv := pickSRV(ans)

	return srvToStr(srv, portStr), err
}

// SRV calls the SRV method on the DefaultSRVClient
func SRV(hostname string) (string, error) {
	return DefaultSRVClient.SRV(hostname)
}

// SRVContext calls the SRVContext method on the DefaultSRVClient
func SRVContext(ctx context.Context, hostname string) (string, error) {
	return DefaultSRVClient.SRVContext(ctx, hostname)
}

// SRV calls SRVContext with an empty context
func (sc *SRVClient) SRV(hostname string) (string, error) {
	return sc.SRVContext(context.Background(), hostname)
}

// SRVContext will perform a SRV request on the given hostname, and then choose
// one of the returned entries randomly based on the priority and weight fields
// it sees. It will return the address ("host:port") of the winning entry, or an
// error if the query couldn't be made or it returned no entries. If the DNS
// server provided the A records for the hosts, then the result will have the
// target replaced with its respective IP.
//
// If the given hostname already has a ":port" appended to it, only the ip will
// be looked up from the SRV request, but the port given will be returned
//
// If the given hostname is "ip:port", it'll just immediately return what you
// sent.
func (sc *SRVClient) SRVContext(ctx context.Context, hostname string) (string, error) {
	return sc.srv(ctx, hostname, true, false)
}

// SRVNoTranslate calls the SRVNoTranslate method on the DefaultSRVClient
func SRVNoTranslate(hostname string) (string, error) {
	return DefaultSRVClient.SRVNoTranslate(hostname)
}

// SRVNoTranslateContext calls the SRVNoTranslateContext method on the DefaultSRVClient
func SRVNoTranslateContext(ctx context.Context, hostname string) (string, error) {
	return DefaultSRVClient.SRVNoTranslateContext(ctx, hostname)
}

// SRVNoTranslate is exactly like SRV except it won't translate names to their
// respective IPs
func (sc *SRVClient) SRVNoTranslate(hostname string) (string, error) {
	return sc.SRVNoTranslateContext(context.Background(), hostname)
}

// SRVNoTranslateContext is exactly like SRVContext except it won't translate
// names to their respective IPs
func (sc *SRVClient) SRVNoTranslateContext(ctx context.Context, hostname string) (string, error) {
	return sc.srv(ctx, hostname, false, false)
}

// SRVNoPort calls the SRVNoPort method on the DefaultSRVClient
func SRVNoPort(hostname string) (string, error) {
	return DefaultSRVClient.SRVNoPort(hostname)
}

// SRVNoPortContext calls the SRVNoPortContext method on the DefaultSRVClient
func SRVNoPortContext(ctx context.Context, hostname string) (string, error) {
	return DefaultSRVClient.SRVNoPortContext(ctx, hostname)
}

// SRVNoPort behaves the same as SRV, but the returned address string will not
// contain the port
func (sc *SRVClient) SRVNoPort(hostname string) (string, error) {
	return sc.SRVNoPortContext(context.Background(), hostname)
}

// SRVNoPortContext behaves the same as SRVContext, but the returned address string
// will not contain the port
func (sc *SRVClient) SRVNoPortContext(ctx context.Context, hostname string) (string, error) {
	addr, err := sc.SRVContext(ctx, hostname)
	if err != nil {
		return "", err
	}

	host, _, err := net.SplitHostPort(addr)
	return host, err
}

// SRVNoCacheContext calls SRVContext but ignores the cache
func (sc *SRVClient) SRVNoCacheContext(ctx context.Context, hostname string) (string, error) {
	return sc.srv(ctx, hostname, true, true)
}

// SRVStats contains lifetime counts for various statistics
type SRVStats struct {
	UDPQueries         int64
	TCPQueries         int64
	TruncatedResponses int64
	ExchangeErrors     int64
	CacheLastHits      int64
	CacheLastMisses    int64
	InFlightHits       int64
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
		InFlightHits:       atomic.LoadInt64(&sc.numInFlightHits),
	}
}

// AllSRV calls the AllSRV method on the DefaultSRVClient
func AllSRV(hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRV(hostname)
}

// AllSRVContext calls the AllSRVContext method on the DefaultSRVClient
func AllSRVContext(ctx context.Context, hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRVContext(ctx, hostname)
}

// AllSRVTranslate calls the AllSRVTranslate method on the DefaultSRVClient
func AllSRVTranslate(hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRVTranslate(hostname)
}

// AllSRVTranslateContext calls the AllSRVTranslateContext method on the
// DefaultSRVClient
func AllSRVTranslateContext(ctx context.Context, hostname string) ([]string, error) {
	return DefaultSRVClient.AllSRVTranslateContext(ctx, hostname)
}

func (sc *SRVClient) allSRV(ctx context.Context, hostname string, translateIPs bool, skipCache bool) ([]string, error) {
	var ogPort string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		ogPort = parts[1]
	}

	ans, err := sc.lookupSRV(ctx, hostname, translateIPs, skipCache)
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

// AllSRV calls AllSRVContext with an empty context
func (sc *SRVClient) AllSRV(hostname string) ([]string, error) {
	return sc.AllSRVContext(context.Background(), hostname)
}

// AllSRVContext returns the list of all hostnames and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
// AllSRVContext will NOT replace hostnames with their respective IPs
func (sc *SRVClient) AllSRVContext(ctx context.Context, hostname string) ([]string, error) {
	return sc.allSRV(ctx, hostname, false, false)
}

// AllSRVTranslate calls AllSRVTranslateContext with an empty context
func (sc *SRVClient) AllSRVTranslate(hostname string) ([]string, error) {
	return sc.AllSRVTranslateContext(context.Background(), hostname)
}

// AllSRVTranslateContext returns the list of all IPs and ports for the SRV lookup
// The results are sorted by priority and then weight. Like SRV, if hostname
// contained a port then the port on all results will be replaced with the
// originally-passed port
func (sc *SRVClient) AllSRVTranslateContext(ctx context.Context, hostname string) ([]string, error) {
	return sc.allSRV(ctx, hostname, true, false)
}

// AllSRVNoCacheContext calls AllSRVContext but ignores the cache
func (sc *SRVClient) AllSRVNoCacheContext(ctx context.Context, hostname string) ([]string, error) {
	return sc.allSRV(ctx, hostname, false, true)
}

// MaybeSRV calls the MaybeSRV method on the DefaultSRVClient
func MaybeSRV(host string) string {
	return DefaultSRVClient.MaybeSRV(host)
}

// MaybeSRV calls MaybeSRVContext with an empty context
func (sc *SRVClient) MaybeSRV(host string) string {
	return sc.MaybeSRVContext(context.Background(), host)
}

// MaybeSRVContext attempts a SRV lookup if the host doesn't contain a port and
// if the SRV lookup succeeds it'll rewrite the host and return it with the
// lookup result. If it fails it'll just return the host originally sent
func (sc *SRVClient) MaybeSRVContext(ctx context.Context, host string) string {
	if _, p, _ := net.SplitHostPort(host); p == "" {
		if addr, err := sc.SRVContext(ctx, host); err == nil {
			host = addr
		}
	}
	return host
}

var (
	randPool = sync.Pool{
		New: func() interface{} {
			// TODO: replace with math/rand/v2 once we can drop < go1.22
			return rand.New(rand.NewSource(time.Now().UnixNano()))
		},
	}
)

func pickSRV(srvs []*dns.SRV) *dns.SRV {
	lowPrio := srvs[0].Priority
	picks := make([]*dns.SRV, 0, len(srvs))
	weights := make([]int, 0, len(srvs))
	var sum int

	for i := range srvs {
		if srvs[i].Priority < lowPrio {
			picks = picks[:0]
			weights = weights[:0]
			sum = 0
			lowPrio = srvs[i].Priority
		}
		if srvs[i].Priority == lowPrio {
			picks = append(picks, srvs[i])
			weights = append(weights, int(srvs[i].Weight))
			sum += int(srvs[i].Weight)
		}
	}

	if len(picks) == 1 {
		return picks[0]
	}

	if sum > 0 {
		rand := randPool.Get().(*rand.Rand)
		defer randPool.Put(rand)
		r := rand.Intn(sum)
		for i := range weights {
			r -= weights[i]
			if r < 0 {
				return picks[i]
			}
		}
	}
	return picks[0]
}

// MaybeSRVURL calls the MaybeSRVURL method on the DefaultSRVClient
func MaybeSRVURL(host string) string {
	return DefaultSRVClient.MaybeSRVURL(host)
}

// MaybeSRVURLContext calls the MaybeSRVURLContext method on the DefaultSRVClient
func MaybeSRVURLContext(ctx context.Context, host string) string {
	return DefaultSRVClient.MaybeSRVURLContext(ctx, host)
}

// MaybeSRVURL calls MaybeSRVURLContext with an empty context
func (sc *SRVClient) MaybeSRVURL(host string) string {
	return sc.MaybeSRVURLContext(context.Background(), host)
}

// MaybeSRVURLContext calls MaybeSRVContext and also prepends http:// if no
// scheme was sent
func (sc *SRVClient) MaybeSRVURLContext(ctx context.Context, host string) string {
	host = sc.MaybeSRVContext(ctx, host)
	if !strings.Contains(host, "://") {
		return "http://" + host
	}
	return host
}
