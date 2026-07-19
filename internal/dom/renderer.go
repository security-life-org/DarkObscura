package dom

import (
	"context"
	"errors"
)

// ErrHeadlessUnavailable is returned by Render when the binary was built without
// the headless renderer (i.e. without `-tags chromedp`).
var ErrHeadlessUnavailable = errors.New("headless renderer not built: rebuild with -tags chromedp (requires a local Chrome/Chromium)")

// Rendered is the result of executing a page in a real browser.
type Rendered struct {
	HTML      string   // the fully-rendered DOM after JS execution
	Endpoints []string // absolute URLs requested at runtime (fetch/XHR/scripts/ws)
}

// Render loads url in a headless browser and returns the rendered DOM plus the
// endpoints the page requested at runtime. It returns ErrHeadlessUnavailable
// unless the binary was built with `-tags chromedp`.
func Render(ctx context.Context, url string) (*Rendered, error) {
	return render(ctx, url)
}

// Available reports whether a headless renderer is compiled into this binary.
func Available() bool { return headlessAvailable }
