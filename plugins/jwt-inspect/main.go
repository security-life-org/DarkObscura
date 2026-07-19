// Command jwt-inspect is a sample DarkObscura WASM plugin. It scans a captured
// flow (JSON) for JWTs and flags weak ones (alg=none, HS256 with a guessable
// secret marker). Build with:
//
//	GOOS=wasip1 GOARCH=wasm go build -o jwt-inspect.wasm ./plugins/jwt-inspect
//
// It implements the DarkObscura plugin ABI (see internal/wasm): it exports
// `alloc` and `analyze`, and imports host `log`/`emit_finding` from the
// "dobscura" module.
//
//go:build wasip1

package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"unsafe"
)

//go:wasmimport dobscura log
func hostLog(ptr, size uint32)

//go:wasmimport dobscura emit_finding
func hostEmitFinding(ptr, size uint32)

// main is required by the Go toolchain but does nothing; the host drives the
// exported functions directly.
func main() {}

// buffers pins allocations so the host-written data is not GC'd before analyze
// reads it.
var buffers = map[uint32][]byte{}

//go:wasmexport alloc
func alloc(size uint32) uint32 {
	buf := make([]byte, size)
	ptr := uint32(uintptr(unsafe.Pointer(&buf[0])))
	buffers[ptr] = buf
	return ptr
}

func writeString(s string) (uint32, uint32) {
	b := []byte(s)
	if len(b) == 0 {
		return 0, 0
	}
	ptr := uint32(uintptr(unsafe.Pointer(&b[0])))
	buffers[ptr] = b
	return ptr, uint32(len(b))
}

func logf(s string) {
	p, n := writeString(s)
	if n > 0 {
		hostLog(p, n)
	}
}

func emit(class, severity, detail string) {
	f := map[string]string{"class": class, "severity": severity, "detail": detail}
	blob, _ := json.Marshal(f)
	p, n := writeString(string(blob))
	if n > 0 {
		hostEmitFinding(p, n)
	}
}

type flow struct {
	ReqHeader  map[string]string `json:"req_header"`
	RespHeader map[string]string `json:"resp_header"`
	ReqBody    []byte            `json:"req_body"`
	RespBody   []byte            `json:"resp_body"`
}

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

//go:wasmexport analyze
func analyze(ptr, size uint32) {
	data := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
	var f flow
	if err := json.Unmarshal(data, &f); err != nil {
		logf("jwt-inspect: bad flow json")
		return
	}
	haystack := strings.Join(values(f.ReqHeader), " ") + " " +
		strings.Join(values(f.RespHeader), " ") + " " +
		string(f.ReqBody) + " " + string(f.RespBody)

	for _, tok := range jwtRe.FindAllString(haystack, -1) {
		parts := strings.Split(tok, ".")
		if len(parts) < 2 {
			continue
		}
		hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		var h struct {
			Alg string `json:"alg"`
		}
		_ = json.Unmarshal(hdr, &h)
		switch strings.ToLower(h.Alg) {
		case "none":
			emit("jwt-alg-none", "high", "JWT accepts alg=none — signature can be stripped")
		case "hs256", "hs384", "hs512":
			emit("jwt-hmac", "info", "HMAC-signed JWT ("+h.Alg+") — test for weak/guessable secret")
		}
	}
}

func values(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
