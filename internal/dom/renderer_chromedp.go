//go:build chromedp

package dom

import (
	"context"
	"sort"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// headlessAvailable is true when compiled with -tags chromedp.
const headlessAvailable = true

// render executes url in a headless Chrome, waits for the app to settle, and
// returns the rendered DOM plus every runtime-requested URL (fetch/XHR/script/
// websocket) — the endpoints a static crawler cannot see.
func render(ctx context.Context, url string) (*Rendered, error) {
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
		)...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	runCtx, cancelRun := context.WithTimeout(browserCtx, 30*time.Second)
	defer cancelRun()

	endpoints := map[string]bool{}
	chromedp.ListenTarget(runCtx, func(ev interface{}) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			if e.Request != nil && e.Request.URL != "" {
				endpoints[e.Request.URL] = true
			}
		}
	})

	var html string
	err := chromedp.Run(runCtx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(2500*time.Millisecond), // let the SPA render / fire XHRs
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	if err != nil {
		return nil, err
	}

	eps := make([]string, 0, len(endpoints))
	for u := range endpoints {
		eps = append(eps, u)
	}
	sort.Strings(eps)
	return &Rendered{HTML: html, Endpoints: eps}, nil
}
