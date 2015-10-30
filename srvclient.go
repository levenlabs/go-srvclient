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
)

func init() {
	go dnsConfigLoop()
}

func lookupSRV(hostname string) (*dns.Msg, error) {
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

	for _, server := range cfg.servers {
		res, _, err := c.Exchange(m, server+":53")
		if err != nil {
			continue
		}
		if res.Rcode != dns.RcodeFormatError {
			return res, nil
		}

		// At this point we got a response, but it was just to tell us that
		// edns0 isn't supported, so we try again without it
		m2 := new(dns.Msg)
		m2.SetQuestion(fqdn, dns.TypeSRV)
		res, _, err = c.Exchange(m2, server+":53")
		if err == nil {
			return res, nil
		}
	}

	return nil, errors.New("no available nameservers")
}

// SRV will perform a SRV request on the given hostname, and then choose one of
// the returned entries randomly based on the priority and weight fields it
// sees. It will return the address ("host:port") of the winning entry, or an
// error if the query couldn't be made or it returned no entries.
//
// If the given hostname already has a ":port" appended to it, only the ip will
// be looked up from the SRV request, but the port given will be returned
func SRV(hostname string) (string, error) {

	var portStr string
	if parts := strings.Split(hostname, ":"); len(parts) == 2 {
		hostname = parts[0]
		portStr = parts[1]
	}

	res, err := lookupSRV(hostname)
	if err != nil {
		return "", err
	}

	if len(res.Answer) == 0 {
		return "", fmt.Errorf("No SRV records for %q", hostname)
	}

	ans := make([]*dns.SRV, len(res.Answer))
	for i := range res.Answer {
		if ansSRV, ok := res.Answer[i].(*dns.SRV); ok {
			ans[i] = ansSRV
		}
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
