package srvclient

import (
	. "testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testHostname = "srv.test.test"
var testHostnameNoSRV = "test.test"
var testHostnameTruncated = "trunc.test.test"

func init() {
	rr := func(s string) dns.RR {
		m, _ := dns.NewRR(s)
		return m
	}

	handleRequest := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		if r.Question[0].Name == dns.Fqdn(testHostname) {
			m.Answer = []dns.RR{
				rr("srv.test. 60 IN SRV 0 0 1000 1.srv.test."),
				rr("srv.test. 60 IN SRV 0 0 1001 2.srv.test."),
			}
			m.Extra = []dns.RR{
				rr("1.srv.test. 60 IN A 10.0.0.1"),
				rr("2.srv.test. 60 IN AAAA 2607:5300:60:92e7::1"),
			}
		} else if r.Question[0].Name == dns.Fqdn(testHostnameNoSRV) {
			m.Answer = []dns.RR{
				rr("test.test. 60 IN A 11.0.0.1"),
			}
		} else if r.Question[0].Name == dns.Fqdn(testHostnameTruncated) {
			m.Answer = []dns.RR{
				rr("srv.test. 60 IN SRV 0 0 1000 1.srv.test."),
				rr("srv.test. 60 IN SRV 0 0 1001 2.srv.test."),
			}
			m.Extra = []dns.RR{
				rr("1.srv.test. 60 IN A 10.0.0.1"),
				rr("2.srv.test. 60 IN AAAA 2607:5300:60:92e7::1"),
			}
			m.Truncated = true
		}
		w.WriteMsg(m)
	}

	server := &dns.Server{
		Addr:    ":0",
		Net:     "udp",
		Handler: dns.HandlerFunc(handleRequest),
	}
	go func() {
		err := server.ListenAndServe()
		panic(err)
	}()
	// give the goroutine a chance to start
	<-time.After(100 * time.Millisecond)
	// immediately call this again since this will block until the previous call
	// is finished
	server.ListenAndServe()

	//override ResolverAddrs with our own server we just started
	DefaultSRVClient.ResolverAddrs = []string{server.PacketConn.LocalAddr().String(), "8.8.8.8:53"}
}

func testDistr(srvs []*dns.SRV) map[string]int {
	m := map[string]int{}
	for i := 0; i < 1000; i++ {
		s := pickSRV(srvs)
		m[s.Target]++
	}
	return m
}

func TestLookupSRV(t *T) {
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

	rr, err := DefaultSRVClient.lookupSRV(testHostname, false)
	require.Nil(t, err)
	assertHasSRV("1.srv.test.", 1000, rr)
	assertHasSRV("2.srv.test.", 1001, rr)

	rr, err = DefaultSRVClient.lookupSRV(testHostname, true)
	require.Nil(t, err)
	assertHasSRV("10.0.0.1", 1000, rr)
	assertHasSRV("2607:5300:60:92e7::1", 1001, rr)
}

func TestSRV(t *T) {
	r, err := SRV(testHostname)
	require.Nil(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")

	r, err = SRV(testHostname + ":9999")
	require.Nil(t, err)
	assert.True(t, r == "10.0.0.1:9999" || r == "[2607:5300:60:92e7::1]:9999")

	r, err = SRV("10.0.0.2:9999")
	require.Nil(t, err)
	assert.Equal(t, "10.0.0.2:9999", r)
}

func TestSRVTruncated(t *T) {
	// these should hit local and then google but we should prefer local
	r, err := SRV(testHostnameTruncated)
	assert.Equal(t, dns.ErrTruncated, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
}

func TestSRVNoPort(t *T) {
	r, err := SRVNoPort(testHostname)
	require.Nil(t, err)
	assert.True(t, r == "10.0.0.1" || r == "2607:5300:60:92e7::1")
}

func TestAllSRV(t *T) {
	r, err := AllSRV(testHostname)
	require.Nil(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "1.srv.test.:1000")
	assert.Contains(t, r, "2.srv.test.:1001")

	r, err = AllSRV(testHostname + ":9999")
	require.Nil(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "1.srv.test.:9999")
	assert.Contains(t, r, "2.srv.test.:9999")
}

func TestPickSRV(t *T) {
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

func TestMaybeSRV(t *T) {
	r := MaybeSRV(testHostnameNoSRV)
	assert.Equal(t, testHostnameNoSRV, r)

	hp := testHostname + ":80"
	r = MaybeSRV(hp)
	assert.Equal(t, hp, r)

	r = MaybeSRV(testHostname)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
}

func TestLastCache(t *T) {
	cl := new(SRVClient)
	cl.EnableCacheLast()
	cl.ResolverAddrs = DefaultSRVClient.ResolverAddrs

	_, err := cl.SRV(testHostname)
	require.Nil(t, err)

	_, err = cl.SRV("fail")
	assert.NotNil(t, err)
	assert.IsType(t, &ErrNotFound{}, err)

	cl.ResolverAddrs = nil

	r, err := cl.SRV(testHostname)
	require.Nil(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
	assert.Len(t, cl.cacheLast, 1)

	cl.cacheLast = nil
	_, err = cl.SRV(testHostname)
	assert.NotNil(t, err)
	assert.IsType(t, &ErrNotFound{}, err)
}

func TestMaybeSRVURL(t *T) {
	withScheme := "http://" + testHostnameNoSRV
	r := MaybeSRVURL(withScheme)
	assert.Equal(t, withScheme, r)

	r = MaybeSRVURL(testHostnameNoSRV)
	assert.Equal(t, withScheme, r)

	r = MaybeSRVURL(testHostname)
	assert.True(t, r == "http://10.0.0.1:1000" || r == "http://[2607:5300:60:92e7::1]:1001")
}

func TestPreprocess(t *T) {
	client := SRVClient{}
	client.ResolverAddrs = DefaultSRVClient.ResolverAddrs
	client.Preprocess = func(m *dns.Msg) {
		m.Answer = m.Answer[:1]
	}

	r, err := client.AllSRV(testHostname)
	require.Nil(t, err)
	assert.Len(t, r, 1)
	assert.Contains(t, r, "1.srv.test.:1000")

	str := client.MaybeSRV(testHostname)
	assert.Equal(t, str, "10.0.0.1:1000")

	str, err = client.SRVNoPort(testHostname)
	require.Nil(t, err)
	assert.Equal(t, str, "10.0.0.1")
}
