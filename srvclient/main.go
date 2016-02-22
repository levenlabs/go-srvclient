package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

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
	l.Parse()
	argv := l.ParamRest()

	if len(argv) < 1 {
		fmt.Print(l.Help())
		exit(1)
	}

	sc := srvclient.SRVClient{}
	resolvers, _ := l.ParamStr("--resolvers")
	for _, r := range strings.Split(resolvers, ",") {
		if net.ParseIP(r) != nil {
			r += ":53"
		}
		if r != "" {
			sc.ResolverAddrs = append(sc.ResolverAddrs, r)
		}
	}

	r, err := sc.SRV(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving %q: %s\n", os.Args[1], err)
		os.Exit(2)
	}

	fmt.Println(r)
}

func exit(i int) {
	time.Sleep(100 * time.Millisecond)
	os.Exit(i)
}
