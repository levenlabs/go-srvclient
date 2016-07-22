# go-srvclient

A simple package for resolving SRV records being served by
[skydns](https://github.com/skynetservices/skydns), according to the algorithm
set forth in that project's README. It simply takes in a hostname and does a SRV
request against it. It wil then look at all the returned entries and make a
weighted random choice of one of them, returning a string which is the
`"host:port"` of the picked entry.

Does not work on Windows.

## Install

    go get github.com/levenlabs/go-srvclient

## Example

```go
package main

import "github.com/levenlabs/go-srvclient"

func main() {
	addr, err := srvclient.SRV("foo.skydns.local")
	if err != nil {
		fmt.Fatal(err)
	}

	log.Printf("%s was chosen!", addr)
}
```

## Binary client

This project also has an installable binary client which can be easily used. It
can be installed with:

    go get github.com/levenlabs/go-srvclient/srvclient

And used like so:

    # srvclient some.host.name
    8.9.10.11:1213
