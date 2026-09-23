// Package eventbus provides a small in-process publish/subscribe bus used to
// decouple campaign, proxy, and feed producers from their consumers inside the
// unified evilgophish application.
package eventbus

import "sync"

// Event is a single event on the bus. Topic selects the subscriber set and
// Payload carries the raw bytes (for feed events this is the JSON wire
// message shared with the live feed).
type Event struct {
	Topic   string
	Payload []byte
}

// Bus is a concurrent publish/subscribe hub. Subscribers register per topic.
// Publish never blocks: if a subscriber's buffer is full the event is dropped
// for that subscriber (slow consumers are intentionally shed, mirroring the
// feed hub's behavior).
type Bus struct {
	mu   sync.RWMutex
	subs map[string]map[chan Event]struct{}
}

// New creates an empty bus.
func New() *Bus {
	return &Bus{
		subs: make(map[string]map[chan Event]struct{}),
	}
}

// Subscribe registers a buffered channel that receives events for the given
// topic. Callers must not send on the returned channel; use it only for
// receiving and for Unsubscribe.
func (b *Bus) Subscribe(topic string, buf int) chan Event {
	ch := make(chan Event, buf)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[topic] == nil {
		b.subs[topic] = make(map[chan Event]struct{})
	}
	b.subs[topic][ch] = struct{}{}
	return ch
}

// Unsubscribe removes a previously subscribed channel.
func (b *Bus) Unsubscribe(topic string, ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if subs, ok := b.subs[topic]; ok {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(b.subs, topic)
		}
	}
}

// Publish delivers the event to every subscriber of the topic without
// blocking. Empty topics and nil payloads are ignored.
func (b *Bus) Publish(topic string, payload []byte) {
	if len(topic) == 0 || payload == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs[topic] {
		select {
		case ch <- Event{Topic: topic, Payload: payload}:
		default:
			// slow consumer: drop the event for this subscriber
		}
	}
}