package srvclient

import (
	. "testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
