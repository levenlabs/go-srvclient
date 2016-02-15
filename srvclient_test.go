package srvclient

import (
	. "testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"time"
)

var regHostname = "mysuperfancyapi.com"
var srvHostname = "_srv-client-test._tcp.mysuperfancyapi.com"
var singleSrvHostname = "_srv-client-test2._tcp.mysuperfancyapi.com"

func testDistr(srvs []*dns.SRV) map[string]int {
	m := map[string]int{}
	for i := 0; i < 1000; i++ {
		s := pickSRV(srvs)
		m[s.Target]++
	}
	return m
}

func TestSRV(t *T) {
	_, err := SRV(regHostname)
	assert.NotNil(t, err)

	r, err := SRV(singleSrvHostname)
	require.Nil(t, err)
	assert.Contains(t, r, ".mysuperfancyapi.com.:1")

	r, err = SRV(srvHostname + ":9999")
	require.Nil(t, err)
	assert.Contains(t, r, ".mysuperfancyapi.com.:9999")
}

func TestSRVNoPort(t *T) {
	_, err := SRVNoPort(regHostname)
	assert.NotNil(t, err)

	r, err := SRVNoPort(singleSrvHostname)
	require.Nil(t, err)
	assert.Contains(t, r, ".mysuperfancyapi.com.")
}

func TestAllSRV(t *T) {
	_, err := AllSRV(regHostname)
	assert.NotNil(t, err)

	r, err := AllSRV(srvHostname)
	require.Nil(t, err)
	require.Len(t, r, 3)
	assert.Contains(t, r[0], ".mysuperfancyapi.com.:8079")
	assert.Contains(t, r[1], ".mysuperfancyapi.com.:8080")
	assert.Contains(t, r[2], ".mysuperfancyapi.com.:8081")

	r, err = AllSRV(srvHostname + ":9999")
	require.Nil(t, err)
	require.Len(t, r, 3)
	assert.Contains(t, r[0], ".mysuperfancyapi.com.:9999")
	assert.Contains(t, r[1], ".mysuperfancyapi.com.:9999")
	assert.Contains(t, r[2], ".mysuperfancyapi.com.:9999")
}

func TestPickSRV(t *T) {
	srvs := []*dns.SRV{
		{Target: "a", Priority: 1, Weight: 100},
		{Target: "b", Priority: 1, Weight: 100},
	}

	m := testDistr(srvs)
	assert.True(t, len(m) == 2)
	assert.True(t, m["a"] > 0)
	assert.True(t, m["b"] > 0)

	srvs = []*dns.SRV{
		{Target: "a", Priority: 2, Weight: 100},
		{Target: "b", Priority: 1, Weight: 100},
		{Target: "c", Priority: 2, Weight: 100},
		{Target: "d", Priority: 1, Weight: 100},
	}

	m = testDistr(srvs)
	assert.True(t, len(m) == 2)
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
	r := MaybeSRV(regHostname)
	assert.Equal(t, regHostname, r)

	hp := singleSrvHostname + ":80"
	r = MaybeSRV(hp)
	assert.Equal(t, hp, r)

	r = MaybeSRV(singleSrvHostname)
	// the beginning part of the hostname is random, we only care that it
	// appended the port (1 in this case)
	assert.Contains(t, r, ".mysuperfancyapi.com.:1")
}

func TestSRVReplace(t *T) {
	_getCFGServers := getCFGServers
	defer func() {
		getCFGServers = _getCFGServers
	}()

	handleRequest := func(w dns.ResponseWriter, r *dns.Msg) {
		require.Len(t, r.Question, 1)
		require.Equal(t, "srv.test.com.", r.Question[0].Name)

		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{
			&dns.SRV{
				Hdr: dns.RR_Header{
					Name: "srv.test.com.",
					Rrtype: dns.TypeSRV,
					Class: dns.ClassINET,
					Ttl: 60,
				},
				Port: 1000,
				Target: "1.srv.test.com.",
			},
			&dns.SRV{
				Hdr: dns.RR_Header{
					Name: "srv.test.com.",
					Rrtype: dns.TypeSRV,
					Class: dns.ClassINET,
					Ttl: 60,
				},
				Port: 1001,
				Target: "2.srv.test.com.",
			},
		}
		m.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name: "1.srv.test.com.",
					Rrtype: dns.TypeA,
					Class: dns.ClassINET,
					Ttl: 60,
				},
				A: net.ParseIP("10.0.0.1"),
			},
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name: "2.srv.test.com.",
					Rrtype: dns.TypeAAAA,
					Class: dns.ClassINET,
					Ttl: 60,
				},
				AAAA: net.ParseIP("2607:5300:60:92e7::1"),
			},
		}
		err := w.WriteMsg(m)
		require.Nil(t, err)
	}

	server := &dns.Server{
		Addr: ":0",
		Net: "udp",
		Handler: dns.HandlerFunc(handleRequest),
	}
	go func(){
		err := server.ListenAndServe()
		panic(err)
	}()
	// give the goroutine a chance to start
	<-time.After(100 * time.Millisecond)
	// immediately call this again since this will block until the previous call
	// is finished
	err := server.ListenAndServe()
	require.NotNil(t, err)
	require.Equal(t, "dns: server already started", err.Error())
	require.NotNil(t, server.PacketConn)

	addrs := []string{server.PacketConn.LocalAddr().String()}
	//override getCFGServers with our own server we just started
	getCFGServers = func(cfg *dnsConfig) []string {
		return addrs
	}

	srvs, err := DefaultSRVClient.lookupSRV("srv.test.com", true)
	require.Nil(t, err)
	require.Len(t, srvs, 2)

	assert.Equal(t, srvs[0].Target, "10.0.0.1")
	assert.EqualValues(t, srvs[0].Port, 1000)
	assert.Equal(t, srvs[1].Target, "2607:5300:60:92e7::1")
	assert.EqualValues(t, srvs[1].Port, 1001)
}
