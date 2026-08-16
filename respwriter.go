package scanguard

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// Response observation is the most dangerous thing this plugin does, and it is
// worth being explicit about why.
//
// Detecting 404 floods and brute-force attempts requires knowing what the backend
// answered, which means wrapping http.ResponseWriter. A wrapper that implements
// only WriteHeader and Write silently strips http.Flusher and http.Hijacker from
// everything further down the chain — which breaks WebSocket upgrades, Server-Sent
// Events and gRPC streaming on every route the middleware touches. That is
// traefik#10269, open since 2023, and it fails weeks later as "my chat app
// stopped working", never as an error at deploy time.
//
// Three defences are applied here:
//
//  1. The wrapper forwards Flush, Hijack, ReadFrom and Push explicitly.
//  2. Requests that are protocol upgrades are never wrapped at all, so a
//     WebSocket handshake reaches the backend with the original writer intact.
//  3. If a delegation ever fails because the underlying writer does not implement
//     the interface, it is reported once, loudly. A degraded stream that says so
//     is recoverable; a silent one is not.

// responseObserver records the status code a backend returned.
type responseObserver struct {
	http.ResponseWriter
	instance string
	status   int
	written  bool
}

func newResponseObserver(rw http.ResponseWriter, instance string) *responseObserver {
	return &responseObserver{ResponseWriter: rw, instance: instance, status: http.StatusOK}
}

func (o *responseObserver) WriteHeader(code int) {
	if !o.written {
		o.status = code
		o.written = true
	}
	o.ResponseWriter.WriteHeader(code)
}

func (o *responseObserver) Write(b []byte) (int, error) {
	if !o.written {
		// An implicit 200: the handler wrote a body without calling WriteHeader.
		o.status = http.StatusOK
		o.written = true
	}
	return o.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer. Server-Sent Events depend on this;
// without it, events queue in a buffer and the client sees nothing until the
// response ends.
func (o *responseObserver) Flush() {
	f, ok := o.ResponseWriter.(http.Flusher)
	if !ok {
		warnOnce(o.instance, "flusher-unavailable",
			"the underlying ResponseWriter does not implement http.Flusher, so streaming responses "+
				"(Server-Sent Events) will buffer on routes using this middleware; set observeResponse: false "+
				"on those routes",
			nil)
		return
	}
	f.Flush()
}

// Hijack forwards to the underlying writer. WebSocket upgrades depend on this.
// In practice this should never be reached, because upgrade requests bypass the
// wrapper entirely — but if it is, an explicit error beats a silent failure.
func (o *responseObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := o.ResponseWriter.(http.Hijacker)
	if !ok {
		warnOnce(o.instance, "hijacker-unavailable",
			"the underlying ResponseWriter does not implement http.Hijacker, so connection upgrades "+
				"(WebSockets) will fail on routes using this middleware; set observeResponse: false on those routes",
			nil)
		return nil, nil, errors.New("scanguard: underlying ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

// ReadFrom preserves the sendfile fast path for large static responses. Without
// it, every file served through this middleware is copied through user space.
func (o *responseObserver) ReadFrom(r io.Reader) (int64, error) {
	if !o.written {
		o.status = http.StatusOK
		o.written = true
	}
	if rf, ok := o.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(o.ResponseWriter, r)
}

// Push forwards HTTP/2 server push.
func (o *responseObserver) Push(target string, opts *http.PushOptions) error {
	if p, ok := o.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Unwrap lets other middleware reach the original writer. Go 1.20+ response
// controllers look for this method.
func (o *responseObserver) Unwrap() http.ResponseWriter { return o.ResponseWriter }

// isUpgrade reports whether a request is asking to change protocols — a WebSocket
// handshake, an HTTP/2 CONNECT, or anything else that will need the raw
// connection. Such requests bypass response observation entirely.
func isUpgrade(req *http.Request) bool {
	if req.Method == http.MethodConnect {
		return true
	}
	if req.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range req.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}
