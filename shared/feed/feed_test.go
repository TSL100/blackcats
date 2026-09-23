package feed

import (
	"testing"
	"time"
)

func TestHubBroadcast(t *testing.T) {
	h := NewHub()
	go h.Run()

	client := &Client{hub: h, send: make(chan []byte, 256)}
	h.register <- client

	h.Broadcast([]byte("hello"))

	select {
	case got := <-client.send:
		if string(got) != "hello" {
			t.Fatalf("expected %q, got %q", "hello", string(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for broadcast")
	}
}

func TestHubUnregister(t *testing.T) {
	h := NewHub()
	go h.Run()

	client := &Client{hub: h, send: make(chan []byte, 256)}
	h.register <- client
	h.unregister <- client

	// The hub must close the client's send channel promptly after
	// unregistering.
	select {
	case _, ok := <-client.send:
		if ok {
			t.Fatal("expected send channel to be closed after unregister")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for send channel close")
	}
}

func TestHubSlowClientDropped(t *testing.T) {
	h := NewHub()
	go h.Run()

	// Unbuffered send channel: the hub can never enqueue a message and will
	// evict the client.
	client := &Client{hub: h, send: make(chan []byte)}
	h.register <- client

	msgs := make([]byte, 0, 300)
	for i := 0; i < 300; i++ {
		msgs = append(msgs, 'x')
	}

	h.Broadcast(msgs)

	time.Sleep(50 * time.Millisecond)

	select {
	case _, ok := <-client.send:
		_ = ok
	case <-time.After(100 * time.Millisecond):
		// Send channel may or may not have been written before eviction.
	}

	// After eviction the hub closes send; a second broadcast must not block.
	done := make(chan struct{})
	go func() {
		h.Broadcast(msgs)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("broadcast blocked after slow-client eviction")
	}
}