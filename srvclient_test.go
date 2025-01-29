package srvclient

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testHostname = "srv.test.test"
var testHostnameNoSRV = "test.test"
var testHostnameTruncated = "trunc.test.test"

func newRR(s string) dns.RR {
	m, _ := dns.NewRR(s)
	return m
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	if r.Question[0].Name == dns.Fqdn(testHostname) {
		m.Answer = []dns.RR{
			newRR("srv.test. 60 IN SRV 0 0 1000 1.srv.test."),
			newRR("srv.test. 60 IN SRV 0 0 1001 2.srv.test."),
		}
		m.Extra = []dns.RR{
			newRR("1.srv.test. 60 IN A 10.0.0.1"),
			newRR("2.srv.test. 60 IN AAAA 2607:5300:60:92e7::1"),
		}
	} else if r.Question[0].Name == dns.Fqdn(testHostnameNoSRV) {
		m.Answer = []dns.RR{
			newRR("test.test. 60 IN A 11.0.0.1"),
		}
	} else if r.Question[0].Name == dns.Fqdn(testHostnameTruncated) {
		m.Answer = []dns.RR{
			newRR("srv.test. 60 IN SRV 0 0 1000 1.srv.test."),
			newRR("srv.test. 60 IN SRV 0 0 1001 2.srv.test."),
		}
		m.Extra = []dns.RR{
			newRR("1.srv.test. 60 IN A 10.0.0.1"),
			newRR("2.srv.test. 60 IN AAAA 2607:5300:60:92e7::1"),
		}
		m.Truncated = true
	}
	w.WriteMsg(m)
}

func tcpHandleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if r.Question[0].Name == dns.Fqdn(testHostnameTruncated) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{
			newRR("srv.test. 60 IN SRV 0 0 1000 1.srv.test."),
			newRR("srv.test. 60 IN SRV 0 0 1001 2.srv.test."),
		}
		m.Extra = []dns.RR{
			newRR("1.srv.test. 60 IN A 10.0.0.2"),
			newRR("2.srv.test. 60 IN AAAA 2607:5300:60:92e7::2"),
		}
		w.WriteMsg(m)
		return
	}
	handleRequest(w, r)
}

func init() {
	// start udp
	server := &dns.Server{
		Addr:    ":0",
		Net:     "udp",
		Handler: dns.HandlerFunc(handleRequest),
	}
	{
		go func() {
			panic(server.ListenAndServe())
		}()
		// give the goroutine a chance to start
		<-time.After(100 * time.Millisecond)
		// immediately call this again since this will block until the previous call
		// is finished
		server.ListenAndServe()
	}

	addr := server.PacketConn.LocalAddr().String()

	// start tcp
	{
		tcpServer := &dns.Server{
			Addr:    addr,
			Net:     "tcp",
			Handler: dns.HandlerFunc(tcpHandleRequest),
		}
		go func() {
			panic(tcpServer.ListenAndServe())
		}()
		// give the goroutine a chance to start
		<-time.After(100 * time.Millisecond)
		// immediately call this again since this will block until the previous call
		// is finished
		tcpServer.ListenAndServe()
	}

	//override ResolverAddrs with our own server we just started
	DefaultSRVClient.ResolverAddrs = []string{addr, "8.8.8.8:53"}
}

func testDistr(srvs []*dns.SRV) map[string]int {
	m := map[string]int{}
	for i := 0; i < 1000; i++ {
		s := pickSRV(srvs)
		m[s.Target]++
	}
	return m
}

func TestLookupSRV(t *testing.T) {
	assertHasSRV := func(host string, port int, srvs []*dns.SRV) {
		found := false
		for _, srv := range srvs {
			if srv.Target == host && srv.Port == uint16(port) {
				found = true
				break
			}
		}
		assert.True(t, found)
	}

	rr, err := DefaultSRVClient.lookupSRV(context.Background(), testHostname, false, false)
	require.NoError(t, err)
	assertHasSRV("1.srv.test.", 1000, rr)
	assertHasSRV("2.srv.test.", 1001, rr)

	rr, err = DefaultSRVClient.lookupSRV(context.Background(), testHostname, true, false)
	require.NoError(t, err)
	assertHasSRV("10.0.0.1", 1000, rr)
	assertHasSRV("2607:5300:60:92e7::1", 1001, rr)
}

func TestSRV(t *testing.T) {
	r, err := SRV(testHostname)
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")

	r, err = SRV(testHostname + ":9999")
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.1:9999" || r == "[2607:5300:60:92e7::1]:9999")

	r, err = SRV("10.0.0.2:9999")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2:9999", r)
}

func TestSRVContext(t *testing.T) {
	r, err := SRVContext(context.Background(), testHostname)
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = SRVContext(ctx, testHostname)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSRVNoTranslate(t *testing.T) {
	r, err := SRVNoTranslate(testHostname)
	require.NoError(t, err)
	assert.True(t, r == "1.srv.test.:1000" || r == "2.srv.test.:1001")

	r, err = SRV("10.0.0.2:9999")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2:9999", r)
}

func TestSRVTruncated(t *testing.T) {
	// these should hit local and then google but we should prefer local
	DefaultSRVClient.IgnoreTruncated = true
	r, err := SRV(testHostnameTruncated)
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")

	// this should hit local over tcp and use that
	DefaultSRVClient.IgnoreTruncated = false
	r, err = SRV(testHostnameTruncated)
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.2:1000" || r == "[2607:5300:60:92e7::2]:1001")
}

func TestSRVNoPort(t *testing.T) {
	r, err := SRVNoPort(testHostname)
	require.NoError(t, err)
	assert.True(t, r == "10.0.0.1" || r == "2607:5300:60:92e7::1")
}

func TestAllSRV(t *testing.T) {
	r, err := AllSRV(testHostname)
	require.NoError(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "1.srv.test.:1000")
	assert.Contains(t, r, "2.srv.test.:1001")

	r, err = AllSRV(testHostname + ":9999")
	require.NoError(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "1.srv.test.:9999")
	assert.Contains(t, r, "2.srv.test.:9999")
}

func TestAllSRVTranslate(t *testing.T) {
	r, err := AllSRVTranslate(testHostname)
	require.NoError(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "10.0.0.1:1000")
	assert.Contains(t, r, "[2607:5300:60:92e7::1]:1001")

	r, err = AllSRVTranslate(testHostname + ":9999")
	require.NoError(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "10.0.0.1:9999")
	assert.Contains(t, r, "[2607:5300:60:92e7::1]:9999")
}

func TestPickSRV(t *testing.T) {
	srvs := []*dns.SRV{
		{Target: "a", Priority: 1, Weight: 100},
		{Target: "b", Priority: 1, Weight: 100},
	}

	m := testDistr(srvs)
	assert.Len(t, m, 2)
	assert.True(t, m["a"] > 0)
	assert.True(t, m["b"] > 0)

	srvs = []*dns.SRV{
		{Target: "a", Priority: 2, Weight: 100},
		{Target: "b", Priority: 1, Weight: 100},
		{Target: "c", Priority: 2, Weight: 100},
		{Target: "d", Priority: 1, Weight: 100},
	}

	m = testDistr(srvs)
	assert.Len(t, m, 2)
	assert.True(t, m["b"] > 0)
	assert.True(t, m["d"] > 0)

	srvs = []*dns.SRV{
		{Target: "a", Priority: 2, Weight: 100},
		{Target: "b", Priority: 1, Weight: 50},
		{Target: "c", Priority: 2, Weight: 100},
		{Target: "d", Priority: 1, Weight: 100},
	}

	for i := 0; i < 25; i++ {
		m = testDistr(srvs)
		assert.True(t, len(m) == 2)
		assert.True(t, m["b"] > 0)
		assert.True(t, m["d"] > 0)
		assert.True(t, m["b"] < m["d"])
	}
}

func TestMaybeSRV(t *testing.T) {
	r := MaybeSRV(testHostnameNoSRV)
	assert.Equal(t, testHostnameNoSRV, r)

	hp := testHostname + ":80"
	r = MaybeSRV(hp)
	assert.Equal(t, hp, r)

	r = MaybeSRV(testHostname)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
}

func TestLastCache(t *testing.T) {
	cl := new(SRVClient)
	cl.EnableCacheLast()
	cl.ResolverAddrs = DefaultSRVClient.ResolverAddrs

	_, err := cl.SRV(testHostname)
	require.NoError(t, err)

	_, err = cl.SRV("fail")
	assert.NotNil(t, err)
	assert.IsType(t, &ErrNotFound{}, err)

	cl.ResolverAddrs = []string{"169.254.0.1:53"}
	// force an update of the config
	cl.lastConfig.updated = time.Time{}

	r, err := cl.SRV(testHostname)
	require.NotNil(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
	assert.Len(t, cl.cacheLast, 1)

	// we don't cache not found errors
	_, err = cl.SRV("fail")
	assert.NotNil(t, err)
	assert.IsType(t, &net.OpError{}, err)

	_, err = cl.SRVNoCacheContext(context.Background(), testHostname)
	assert.NotNil(t, err)
	assert.IsType(t, &net.OpError{}, err)

	_, err = cl.AllSRVNoCacheContext(context.Background(), testHostname)
	assert.NotNil(t, err)
	assert.IsType(t, &net.OpError{}, err)
}

func TestMaybeSRVURL(t *testing.T) {
	withScheme := "http://" + testHostnameNoSRV
	r := MaybeSRVURL(withScheme)
	assert.Equal(t, withScheme, r)

	r = MaybeSRVURL(testHostnameNoSRV)
	assert.Equal(t, withScheme, r)

	r = MaybeSRVURL(testHostname)
	assert.True(t, r == "http://10.0.0.1:1000" || r == "http://[2607:5300:60:92e7::1]:1001")
}

func TestPreprocess(t *testing.T) {
	client := SRVClient{}
	client.ResolverAddrs = DefaultSRVClient.ResolverAddrs
	client.Preprocess = func(m *dns.Msg) {
		m.Answer = m.Answer[:1]
	}

	r, err := client.AllSRV(testHostname)
	require.NoError(t, err)
	assert.Len(t, r, 1)
	assert.Contains(t, r, "1.srv.test.:1000")

	str := client.MaybeSRV(testHostname)
	assert.Equal(t, str, "10.0.0.1:1000")

	str, err = client.SRVNoPort(testHostname)
	require.NoError(t, err)
	assert.Equal(t, str, "10.0.0.1")
}

func TestSingleInFlight(t *testing.T) {
	var count int64

	waitCh := make(chan struct{})

	// start udp
	server := &dns.Server{
		Addr: ":0",
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			atomic.AddInt64(&count, 1)
			<-waitCh
			handleRequest(w, r)
		}),
	}
	{
		go func() {
			panic(server.ListenAndServe())
		}()
		// give the goroutine a chance to start
		<-time.After(100 * time.Millisecond)
		// immediately call this again since this will block until the previous call
		// is finished
		server.ListenAndServe()
	}

	client := SRVClient{}
	client.SingleInFlight = true
	client.ResolverAddrs = []string{server.PacketConn.LocalAddr().String()}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r, err := client.AllSRV(testHostname)
		require.NoError(t, err)
		assert.Len(t, r, 2)
		assert.Contains(t, r, "1.srv.test.:1000")
		assert.Contains(t, r, "2.srv.test.:1001")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r, err := client.SRV(testHostname)
		require.NoError(t, err)
		assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := client.SRVContext(ctx, testHostname)
		assert.Error(t, err, context.Canceled)
	}()

	waitCh <- struct{}{}
	wg.Wait()
	assert.EqualValues(t, 1, atomic.LoadInt64(&count))
	assert.EqualValues(t, 2, client.Stats().InFlightHits)

	// make sure a context cancellation on the first one doesn't break the others
	atomic.StoreInt64(&count, 0)
	atomic.StoreInt64(&client.numInFlightHits, 0)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Microsecond)
		defer cancel()
		_, err := client.SRVContext(ctx, testHostname)
		assert.Error(t, err, context.Canceled)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		r, err := client.SRV(testHostname)
		require.NoError(t, err)
		assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
	}()

	waitCh <- struct{}{}
	wg.Wait()
	assert.EqualValues(t, 1, atomic.LoadInt64(&count))
	assert.EqualValues(t, 1, client.Stats().InFlightHits)

	_, err := client.SRVNoCacheContext(context.Background(), "fail")
	assert.NotNil(t, err)
}
