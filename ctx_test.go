package srvclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func canceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func TestWithoutCancel(t *testing.T) {
	inner, innerFn := context.WithCancel(context.Background())
	var middle context.Context = WithoutCancel(inner)
	outer, outerFn := context.WithCancel(middle)

	assert.False(t, canceled(inner))
	assert.False(t, canceled(middle))
	assert.False(t, canceled(outer))

	innerFn()

	assert.True(t, canceled(inner))
	assert.False(t, canceled(middle))
	assert.False(t, canceled(outer))

	outerFn()

	assert.True(t, canceled(inner))
	assert.False(t, canceled(middle))
	assert.True(t, canceled(outer))

	// make sure the deadline is overridden
	innerDeadline := time.Now().Add(time.Second)
	inner, innerFn = context.WithDeadline(context.Background(), innerDeadline)
	middleDeadline := time.Now().Add(10 * time.Second)
	middle, middleFn := context.WithDeadline(WithoutCancel(inner), middleDeadline)

	d, ok := inner.Deadline()
	require.True(t, ok)
	assert.Equal(t, innerDeadline, d)

	innerFn()

	d, ok = middle.Deadline()
	require.True(t, ok)
	assert.Equal(t, middleDeadline, d)

	middleFn()
}
