package proxy

import "net/http"

// Interceptor lets higher layers (engine, exploit) observe and optionally mutate
// flows as they pass through the proxy. Implementations must be safe for
// concurrent use; hooks are invoked from many goroutines.
type Interceptor interface {
	// OnRequest is called before the request is forwarded upstream. Returning a
	// non-nil *http.Response short-circuits the upstream call (used for fault
	// injection / replay). Returning nil forwards normally.
	OnRequest(req *http.Request) *http.Response
	// OnResponse is called after the upstream response is received, before it is
	// written back to the client.
	OnResponse(req *http.Request, resp *http.Response)
}

// InterceptorFunc adapts plain functions to the Interceptor interface. Either
// field may be nil.
type InterceptorFunc struct {
	Req  func(*http.Request) *http.Response
	Resp func(*http.Request, *http.Response)
}

func (f InterceptorFunc) OnRequest(r *http.Request) *http.Response {
	if f.Req != nil {
		return f.Req(r)
	}
	return nil
}

func (f InterceptorFunc) OnResponse(r *http.Request, resp *http.Response) {
	if f.Resp != nil {
		f.Resp(r, resp)
	}
}
