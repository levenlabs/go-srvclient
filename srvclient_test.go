package srvclient

import (
	. "testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func testDistr(srvs []*dns.SRV) map[string]int {
	m := map[string]int{}
	for i := 0; i < 1000; i++ {
		s := pickSRV(srvs)
		m[s.Target]++
	}
	return m
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
