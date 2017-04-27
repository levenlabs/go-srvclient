package srvclient

import "fmt"

// ErrNotFound is returned when there were no SRV records for the given
// hostname
type ErrNotFound struct {
	hostname string
}

// Error implements the error interface
func (err *ErrNotFound) Error() string {
	return fmt.Sprintf("No SRV records for %q", err.hostname)
}
