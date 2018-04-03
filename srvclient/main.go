package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/levenlabs/go-srvclient"
	"github.com/mediocregopher/lever"
)

func main() {
	l := lever.New("srvclient", &lever.Opts{
		HelpHeader:         "Usage: srvclient [options] <hostname>\n",
		DisallowConfigFile: true,
	})
	l.Add(lever.Param{
		Name:        "--resolvers",
		Description: "Comma separated list of resolver ips or addresses (ip:port) which should be used instead of /etc/resolv.conf",
	})
	l.Add(lever.Param{
		// this matches the flag for dig
		Name:        "--ignore",
		Description: "Whether to ignore truncated responses",
		Flag:        true,
	})
	l.Parse()
	argv := l.ParamRest()

	if len(argv) < 1 {
		fmt.Print(l.Help())
		exit(1)
	}

	sc := new(srvclient.SRVClient)
	resolvers, _ := l.ParamStr("--resolvers")
	for _, r := range strings.Split(resolvers, ",") {
		if net.ParseIP(r) != nil {
			r += ":53"
		}
		if r != "" {
			sc.ResolverAddrs = append(sc.ResolverAddrs, r)
		}
	}

	ignore := l.ParamFlag("--ignore")
	r, err := sc.SRV(argv[0])
	if err != nil && (err != dns.ErrTruncated || !ignore || r == "") {
		fmt.Fprintf(os.Stderr, "error resolving %q: %s\n", argv[0], err)
		os.Exit(2)
	}

	fmt.Println(r)
}

func exit(i int) {
	time.Sleep(100 * time.Millisecond)
	os.Exit(i)
}
