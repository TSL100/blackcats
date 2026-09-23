package eventbus

import (
	"testing"
	"time"
)

func TestPublishSubscribe(t *testing.T) {
	b := New()
	ch := b.Subscribe("feed", 8)

	b.Publish("feed", []byte("hello"))

	select {
	case ev := <-ch:
		if ev.Topic != "feed" || string(ev.Payload) != "hello" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestTopicIsolation(t *testing.T) {
	b := New()
	ch := b.Subscribe("feed", 8)

	b.Publish("other", []byte("nope"))

	select {
	case ev := <-ch:
		t.Fatalf("expected no event on feed topic, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// expected: nothing delivered
	}
}

func TestMultipleSubscribers(t *testing.T) {
	b := New()
	ch1 := b.Subscribe("feed", 8)
	ch2 := b.Subscribe("feed", 8)

	b.Publish("feed", []byte("broadcast"))

	for i, ch := range []chan Event{ch1, ch2} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber %d did not receive event", i)
		}
	}
}

func TestUnsubscribe(t *testing.T) {
	b := New()
	ch := b.Subscribe("feed", 8)
	b.Unsubscribe("feed", ch)

	b.Publish("feed", []byte("gone"))

	select {
	case ev := <-ch:
		t.Fatalf("expected no event after unsubscribe, got %+v", ev)
	case <-time.After(100 * time.Millisecond):
		// expected: nothing delivered
	}
}

func TestSlowConsumerDropped(t *testing.T) {
	b := New()
	ch := b.Subscribe("feed", 1)

	b.Publish("feed", []byte("one"))

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("expected first event")
	}

	// Buffer is full now; a flood must not block the publisher.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish("feed", []byte("flood"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on slow consumer")
	}
}