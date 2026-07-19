// Package proxy implements the DarkObscura MITM proxy: an HTTP/1.1 + HTTP/2
// forward proxy that transparently intercepts TLS via CONNECT, records every
// flow to storage, and fans each exchange out to registered Interceptors.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/security-life-org/DarkObscura/internal/storage"
	"github.com/security-life-org/DarkObscura/pkg/certgen"
	"github.com/security-life-org/DarkObscura/pkg/netutil"
	"golang.org/x/net/http2"
)

// Proxy is a MITM forward proxy.
type Proxy struct {
	ca    *certgen.CA
	store storage.Store
	log   *slog.Logger

	transport *http.Transport

	mu           sync.RWMutex
	interceptors []Interceptor
}

// Options configures a Proxy.
type Options struct {
	CA     *certgen.CA
	Store  storage.Store
	Logger *slog.Logger
	// InsecureUpstream skips upstream TLS verification (common for testing against
	// self-signed targets). Defaults to false.
	InsecureUpstream bool
}

// New constructs a Proxy.
func New(opts Options) *Proxy {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.InsecureUpstream},
	}
	return &Proxy{ca: opts.CA, store: opts.Store, log: log, transport: tr}
}

// Use registers an Interceptor. Interceptors run in registration order.
func (p *Proxy) Use(i Interceptor) {
	p.mu.Lock()
	p.interceptors = append(p.interceptors, i)
	p.mu.Unlock()
}

// ServeHTTP dispatches between plain HTTP proxying and CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

// handlePlain forwards an absolute-form HTTP request and records it.
func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	resp, flow := p.roundTrip(r, "http")
	if resp == nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	body, _ := io.Copy(w, resp.Body)
	_ = body
	p.persist(flow)
}

// handleConnect hijacks the client connection, presents a MITM leaf cert, and
// serves the decrypted stream as HTTP/1.1 or HTTP/2 depending on ALPN.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hij.Hijack()
	if err != nil {
		p.log.Error("hijack failed", "err", err)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		return
	}

	host := r.Host
	tlsConf := p.ca.TLSConfig()
	tlsConf.NextProtos = []string{"h2", "http/1.1"}
	tlsConn := tls.Server(clientConn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		p.log.Debug("mitm handshake failed", "host", host, "err", err)
		tlsConn.Close()
		return
	}

	scheme := "https"
	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = scheme
		req.URL.Host = host
		resp, flow := p.roundTrip(req, scheme)
		if resp == nil {
			http.Error(rw, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
		p.persist(flow)
	})

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	p.serveHTTP1(tlsConn, host, handler)
}

// serveHTTP1 serves sequential HTTP/1.1 requests over a decrypted conn.
func (p *Proxy) serveHTTP1(conn net.Conn, host string, handler http.Handler) {
	defer conn.Close()
	oneShot := &singleConnListener{conn: conn, host: host}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	_ = srv.Serve(oneShot)
}

// roundTrip runs interceptors, forwards upstream, and builds a Flow record.
func (p *Proxy) roundTrip(r *http.Request, scheme string) (*http.Response, *storage.Flow) {
	start := time.Now()
	reqBody := drainBody(r)

	if short := p.fireOnRequest(r); short != nil {
		flow := p.buildFlow(r, short, reqBody, scheme, time.Since(start))
		return short, flow
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = scheme
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	if reqBody != nil {
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.log.Debug("roundtrip error", "url", outReq.URL.String(), "err", err)
		return nil, nil
	}
	p.fireOnResponse(r, resp)
	flow := p.buildFlow(r, resp, reqBody, scheme, time.Since(start))
	return resp, flow
}

func (p *Proxy) buildFlow(r *http.Request, resp *http.Response, reqBody []byte, scheme string, dur time.Duration) *storage.Flow {
	respBody := peekBody(resp)
	return &storage.Flow{
		ID:         netutil.NewID(),
		Timestamp:  time.Now(),
		Scheme:     scheme,
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		ReqHeader:  flatten(r.Header),
		ReqBody:    reqBody,
		Status:     resp.StatusCode,
		RespHeader: flatten(resp.Header),
		RespBody:   respBody,
		DurationMS: dur.Milliseconds(),
	}
}

func (p *Proxy) persist(flow *storage.Flow) {
	if flow == nil || p.store == nil {
		return
	}
	if err := p.store.SaveFlow(flow); err != nil {
		p.log.Warn("persist flow failed", "err", err)
	}
}

func (p *Proxy) fireOnRequest(r *http.Request) *http.Response {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, i := range p.interceptors {
		if resp := i.OnRequest(r); resp != nil {
			return resp
		}
	}
	return nil
}

func (p *Proxy) fireOnResponse(r *http.Request, resp *http.Response) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, i := range p.interceptors {
		i.OnResponse(r, resp)
	}
}

// ListenAndServe starts the proxy on addr until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: p}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	p.log.Info("proxy listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
