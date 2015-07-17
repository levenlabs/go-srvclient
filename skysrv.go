package skysrv

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

// SRV will perform a SRV request on the given hostname, and then choose one of
// the returned entries randomly based on the priority and weight fields it
// sees. It will return the address ("host:port") of the winning entry, or an
// error if the query couldn't be made or it returned no entries
func SRV(hostname string) (string, error) {
	_, srvs, err := net.LookupSRV("", "", hostname)
	if err != nil {
		return "", err
	}

	if len(srvs) == 0 {
		return "", fmt.Errorf("No SRV records for %q", hostname)
	}

	srv := pickSRV(srvs)
	addr := srv.Target + ":" + strconv.Itoa(int(srv.Port))
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

func pickSRV(srvs []*net.SRV) *net.SRV {
	lowPrio := srvs[0].Priority
	picks := make([]*net.SRV, 0, len(srvs))
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
