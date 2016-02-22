// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This file is modified from the original, if we want to use the updated
// version we'll have to do some extra work to consolidate them

package srvclient

import (
	"net"
	"os"
	"time"
)

const resolvFile = "/etc/resolv.conf"

// go's net package used 5 seconds as its reload interval, we might as well too
const reloadInterval = 5 * time.Second

type dnsConfigGet struct {
	cfg dnsConfig
	err error
}

var dnsConfigCh = make(chan dnsConfigGet)

func dnsShouldReload(lastReload time.Time) bool {
	fi, err := os.Stat(resolvFile)
	if err != nil {
		return false
	}
	return lastReload.Before(fi.ModTime())
}

func dnsConfigLoop() {
	var r dnsConfigGet
	r.cfg, r.err = dnsReadConfig(resolvFile)
	tick := time.Tick(reloadInterval)
	lastReload := time.Now()
	for {
		select {
		case dnsConfigCh <- r:
		case <-tick:
			if r.err == nil && !dnsShouldReload(lastReload) {
				continue
			}
			if r.cfg, r.err = dnsReadConfig(resolvFile); r.err == nil {
				lastReload = time.Now()
			}
		}
	}
}

func dnsGetConfig() (dnsConfig, error) {
	r := <-dnsConfigCh
	return r.cfg, r.err
}

type dnsConfig struct {
	servers  []string // servers to use
	search   []string // suffixes to append to local name
	ndots    int      // number of dots in name to trigger absolute lookup
	timeout  int      // seconds before giving up on packet
	attempts int      // lost packets before giving up on server
	rotate   bool     // round robin among servers
}

// See resolv.conf(5) on a Linux machine.
// TODO(rsc): Supposed to call uname() and chop the beginning
// of the host name to get the default search domain.
func dnsReadConfig(filename string) (dnsConfig, error) {
	file, err := open(filename)
	if err != nil {
		return dnsConfig{}, err
	}
	defer file.close()
	conf := dnsConfig{
		ndots:    1,
		timeout:  5,
		attempts: 2,
	}
	for line, ok := file.readLine(); ok; line, ok = file.readLine() {
		f := getFields(line)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver": // add one name server
			if len(f) > 1 && len(conf.servers) < 3 { // small, but the standard limit
				// One more check: make sure server name is
				// just an IP address.  Otherwise we need DNS
				// to look it up.
				if net.ParseIP(f[1]) != nil {
					conf.servers = append(conf.servers, f[1]+":53")
				}
			}

		case "domain": // set search path to just this domain
			if len(f) > 1 {
				conf.search = []string{f[1]}
			}

		case "search": // set search path to given servers
			conf.search = make([]string, len(f)-1)
			for i := 0; i < len(conf.search); i++ {
				conf.search[i] = f[i+1]
			}

		case "options": // magic options
			for i := 1; i < len(f); i++ {
				s := f[i]
				switch {
				case hasPrefix(s, "ndots:"):
					n, _, _ := dtoi(s, 6)
					if n < 1 {
						n = 1
					}
					conf.ndots = n
				case hasPrefix(s, "timeout:"):
					n, _, _ := dtoi(s, 8)
					if n < 1 {
						n = 1
					}
					conf.timeout = n
				case hasPrefix(s, "attempts:"):
					n, _, _ := dtoi(s, 9)
					if n < 1 {
						n = 1
					}
					conf.attempts = n
				case s == "rotate":
					conf.rotate = true
				}
			}
		}
	}
	return conf, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
