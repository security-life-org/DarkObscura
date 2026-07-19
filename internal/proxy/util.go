package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
)

// maxCaptureBytes bounds how much of a body we buffer for storage/analysis.
const maxCaptureBytes = 4 << 20 // 4 MiB

// drainBody reads and replaces r.Body so it can be both recorded and forwarded.
func drainBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(r.Body, maxCaptureBytes))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf
}

// peekBody reads resp.Body up to the cap and replaces it so the caller can still
// stream it back to the client.
func peekBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBytes))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	return buf
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// singleConnListener is a net.Listener that yields exactly one pre-established
// connection, then blocks. It lets us drive http.Serve over a hijacked TLS conn.
type singleConnListener struct {
	conn net.Conn
	host string
	done chan struct{}
	once bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.once {
		if l.done == nil {
			l.done = make(chan struct{})
		}
		<-l.done
		return nil, io.EOF
	}
	l.once = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	if l.done != nil {
		close(l.done)
		l.done = nil
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
