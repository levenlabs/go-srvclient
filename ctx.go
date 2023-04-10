package srvclient

import (
	"context"
	"time"
)

var emptyTime time.Time

type withoutCancel struct {
	context.Context
}

// WithoutCancel returns a context identical to the given one, but which will
// never be canceled, regardless of if the given one is because the context
// methods will only propagate cancellations if the Done() method returns
// non-nil, but we override the Done method to return nil. Additionally,
// this will overwrite the Deadline method to return no deadline so if you
// call WithTimeout/WithDeadline it'll use the new value and not retain
// the parent one if its sooner.
func WithoutCancel(ctx context.Context) context.Context {
	return withoutCancel{ctx}
}

// Done implements the context.Context interface
func (withoutCancel) Done() <-chan struct{} {
	// the context interface specifically allows Done to return nil
	return nil
}

// Deadline implements the context.Context interface
func (withoutCancel) Deadline() (time.Time, bool) {
	return emptyTime, false
}
