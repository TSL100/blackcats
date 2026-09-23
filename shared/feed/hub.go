// Package feed implements the live-feed websocket hub that broadcasts
// campaign events from the gophish and evilginx engines to dashboard clients.
//
// This package is the canonical implementation; the standalone evilfeed
// binary and the unified evilgophish application both build on it.
package feed

import "github.com/gorilla/websocket"

// Client is a single websocket consumer of the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

// Run is the single-threaded event loop that owns the client set. It must be
// started once per hub.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

// Broadcast fans out a message to every registered client. It blocks until
// the hub's event loop has accepted the message.
func (h *Hub) Broadcast(message []byte) {
	h.broadcast <- message
}