package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/levenlabs/go-srvclient"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: srvclient [options] <hostname>\n")
		flag.PrintDefaults()
	}
	resolvers := flag.String("resolvers", "", "Comma separated list of resolver ips or addresses (ip:port) which should be used instead of /etc/resolv.conf")
	// this matches the flag for dig
	ignore := flag.Bool("ignore", false, "Whether to ignore truncated responses")
	flag.Parse()
	argv := flag.Args()

	if len(argv) < 1 {
		flag.Usage()
		exit(1)
	}

	sc := new(srvclient.SRVClient)
	for _, r := range strings.Split(*resolvers, ",") {
		if net.ParseIP(r) != nil {
			r += ":53"
		}
		if r != "" {
			sc.ResolverAddrs = append(sc.ResolverAddrs, r)
		}
	}

	if *ignore {
		sc.IgnoreTruncated = true
	}
	r, err := sc.SRV(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving %q: %s\n", argv[0], err)
		os.Exit(2)
	}

	fmt.Println(r)
}

func exit(i int) {
	time.Sleep(100 * time.Millisecond)
	os.Exit(i)
}
