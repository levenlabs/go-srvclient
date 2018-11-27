package srvclient

import (
	"os"
	"time"

	"github.com/miekg/dns"
)

type clientConfig struct {
	dns.ClientConfig
	updated time.Time
}

const resolvFile = "/etc/resolv.conf"

// go's net package used 5 seconds as its reload interval, we might as well too
const reloadInterval = 5 * time.Second

type dnsConfigGet struct {
	cfg clientConfig
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
	getConfig := func() dnsConfigGet {
		cfg, err := dns.ClientConfigFromFile(resolvFile)
		if err != nil {
			return dnsConfigGet{err: err}
		}
		for i := range cfg.Servers {
			cfg.Servers[i] = cfg.Servers[i] + ":" + cfg.Port
		}

		return dnsConfigGet{
			cfg: clientConfig{
				ClientConfig: *cfg,
				updated:      time.Now(),
			},
		}
	}

	r := getConfig()
	tick := time.Tick(reloadInterval)
	lastReload := time.Now()
	for {
		select {
		case dnsConfigCh <- r:
		case <-tick:
			if r.err == nil && !dnsShouldReload(lastReload) {
				continue
			}
			if r = getConfig(); r.err == nil {
				lastReload = time.Now()
			}
		}
	}
}

func dnsGetConfig() (clientConfig, error) {
	r := <-dnsConfigCh
	return r.cfg, r.err
}
