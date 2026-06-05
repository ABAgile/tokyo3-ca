package portal_test

import (
	"context"

	"github.com/abagile/tokyo3-base/journal"
)

// mockSource is a minimal journal.Source: tests push payloads onto
// out; Subscribe returns out so a tracker's goroutine sees them.
// Close is a no-op.
type mockSource struct {
	out chan journal.Msg
}

func newMockSource() *mockSource {
	return &mockSource{out: make(chan journal.Msg, 16)}
}

func (m *mockSource) Subscribe(_ context.Context, _ int, _ uint64) (<-chan journal.Msg, error) {
	return m.out, nil
}

func (m *mockSource) Close() error { return nil }
