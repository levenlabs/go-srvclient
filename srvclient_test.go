package srvclient

import (
	. "testing"

	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testHostname = "srv.test.com"
var testHostnameNoSRV = "test.com"

func init() {
	rr := func(s string) dns.RR {
		m, _ := dns.NewRR(s)
		return m
	}

	handleRequest := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		if r.Question[0].Name == "srv.test.com." {
			m.Answer = []dns.RR{
				rr("srv.test.com. 60 IN SRV 0 0 1000 1.srv.test.com."),
				rr("srv.test.com. 60 IN SRV 0 0 1001 2.srv.test.com."),
			}
			m.Extra = []dns.RR{
				rr("1.srv.test.com. 60 IN A 10.0.0.1"),
				rr("2.srv.test.com. 60 IN AAAA 2607:5300:60:92e7::1"),
			}
		} else if r.Question[0].Name == "test.com." {
			m.Answer = []dns.RR{
				rr("test.com. 60 IN A 11.0.0.1"),
			}
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

	addrs := []string{server.PacketConn.LocalAddr().String()}
	//override getCFGServers with our own server we just started
	DefaultSRVClient.getCFGServers = func(cfg *dnsConfig) []string {
		return addrs
	}
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
	assertHasSRV("1.srv.test.com.", 1000, rr)
	assertHasSRV("2.srv.test.com.", 1001, rr)

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
	assert.Contains(t, r, "1.srv.test.com.:1000")
	assert.Contains(t, r, "2.srv.test.com.:1001")

	r, err = AllSRV(testHostname + ":9999")
	require.Nil(t, err)
	assert.Len(t, r, 2)
	assert.Contains(t, r, "1.srv.test.com.:9999")
	assert.Contains(t, r, "2.srv.test.com.:9999")
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
	cl := SRVClient{}
	cl.EnableCacheLast()
	cl.getCFGServers = DefaultSRVClient.getCFGServers

	_, err := cl.SRV(testHostname)
	require.Nil(t, err)

	cl.getCFGServers = func(_ *dnsConfig) []string { return []string{} }

	r, err := cl.SRV(testHostname)
	require.Nil(t, err)
	assert.True(t, r == "10.0.0.1:1000" || r == "[2607:5300:60:92e7::1]:1001")
	assert.Len(t, cl.cacheLast, 1)

	cl.cacheLast = nil
	_, err = cl.SRV(testHostname)
	assert.NotNil(t, err)
}
