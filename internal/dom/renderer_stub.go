//go:build !chromedp

package dom

import "context"

// headlessAvailable is false in the default (pure-Go, no-Chrome) build.
const headlessAvailable = false

// render is the no-op fallback: it keeps the default `go build ./...` free of any
// Chrome dependency. Enable the real renderer with `-tags chromedp`.
func render(_ context.Context, _ string) (*Rendered, error) {
	return nil, ErrHeadlessUnavailable
}
