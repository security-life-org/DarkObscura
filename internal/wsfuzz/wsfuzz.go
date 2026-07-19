// Package wsfuzz fuzzes WebSocket endpoints — a surface classic HTTP scanners
// ignore entirely. It connects to a ws:// or wss:// URL, sends a benign baseline
// message, then injects payloads into a message template and inspects the frames
// the server returns for injected-input reflection or database-error signatures.
// Reflection of a raw marker is reported at "possible" confidence (the tool
// cannot prove a browser renders it), while a database error string introduced
// by the payload is deterministic evidence of injection.
package wsfuzz

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/security-life-org/DarkObscura/internal/payloads"
	"github.com/gorilla/websocket"
)

// Finding is a WebSocket observation.
type Finding struct {
	Class      string
	Confidence string // "possible" | "confirmed"
	Payload    string
	Evidence   []string
}

// dbErrorSig matches unmistakable database errors surfaced over the socket.
var dbErrorSig = regexp.MustCompile(`(?i)SQL syntax.*?MySQL|PostgreSQL.*?ERROR|SQLITE_ERROR|ORA-\d{5}|Unclosed quotation mark|MongoError`)

// Fuzzer drives one WebSocket endpoint.
type Fuzzer struct {
	URL      string
	Origin   string // Origin header (some servers require it)
	Template string // message template; the literal FUZZ is replaced with each payload
	Dialer   *websocket.Dialer
	Read     time.Duration // per-message read window
}

// New builds a Fuzzer with sane defaults. template must contain the token FUZZ.
func New(url, template string) *Fuzzer {
	if template == "" {
		template = "FUZZ"
	}
	return &Fuzzer{
		URL: url, Template: template,
		Dialer: websocket.DefaultDialer, Read: 3 * time.Second,
	}
}

func (f *Fuzzer) dial(ctx context.Context) (*websocket.Conn, error) {
	h := http.Header{}
	if f.Origin != "" {
		h.Set("Origin", f.Origin)
	}
	c, _, err := f.Dialer.DialContext(ctx, f.URL, h)
	return c, err
}

// sendRecv sends one message and returns the concatenation of frames received
// within the read window.
func (f *Fuzzer) sendRecv(ctx context.Context, msg string) (string, error) {
	c, err := f.dial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		return "", err
	}
	var sb strings.Builder
	_ = c.SetReadDeadline(time.Now().Add(f.Read))
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			break
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// Run connects, verifies the endpoint is live, then fuzzes reflection and
// injection. It returns confirmed/possible findings.
func (f *Fuzzer) Run(ctx context.Context) ([]Finding, error) {
	// Liveness / baseline.
	if _, err := f.sendRecv(ctx, strings.ReplaceAll(f.Template, "FUZZ", "dobwsbaseline")); err != nil {
		return nil, fmt.Errorf("ws connect: %w", err)
	}

	var out []Finding

	// Reflection probe: a unique marker that, if echoed raw, indicates the input
	// is reflected back to clients (possible stored/reflected XSS via the socket).
	marker := "dobws0refl"
	reflMsg := strings.ReplaceAll(f.Template, "FUZZ", "<svg/onload="+marker+">")
	if resp, err := f.sendRecv(ctx, reflMsg); err == nil && strings.Contains(resp, "<svg/onload="+marker) {
		out = append(out, Finding{
			Class: "ws-reflected-input", Confidence: "possible", Payload: reflMsg,
			Evidence: []string{
				"server echoed the injected markup unescaped in a WebSocket frame",
				"possible XSS if a client renders socket messages as HTML — manual confirmation required",
			},
		})
	}

	// Injection probe: DB error signature introduced by a payload = confirmed.
	for _, p := range payloads.Generate("sqli", payloads.CtxSQL, "ws") {
		msg := strings.ReplaceAll(f.Template, "FUZZ", p.Value)
		resp, err := f.sendRecv(ctx, msg)
		if err != nil {
			continue
		}
		if sig := dbErrorSig.FindString(resp); sig != "" {
			out = append(out, Finding{
				Class: "ws-sqli", Confidence: "confirmed", Payload: msg,
				Evidence: []string{
					"database error returned over the socket: " + sig,
					"verified: a payload reached a SQL interpreter via the WebSocket — SQL injection",
				},
			})
			break
		}
	}
	return out, nil
}
