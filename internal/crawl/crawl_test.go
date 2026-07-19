package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCrawlDiscoversLinksAndForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>
			<a href="/products?id=1">products</a>
			<a href="/about">about</a>
			<a href="https://external.example/x">external</a>
			<form action="/search" method="GET"><input name="q"><input name="cat"></form>
		</body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><a href="/products?id=2&ref=about">more</a></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Crawl(context.Background(), srv.URL+"/", Options{MaxDepth: 2, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	// Endpoints with params discovered (from link query + GET form).
	var hasProducts, hasSearch bool
	for _, e := range res.Endpoints {
		if contains(e, "/products?") {
			hasProducts = true
		}
		if contains(e, "/search?") {
			hasSearch = true
		}
		if contains(e, "external.example") {
			t.Errorf("must not crawl off-origin: %s", e)
		}
	}
	if !hasProducts {
		t.Errorf("expected a /products endpoint with params; got %v", res.Endpoints)
	}
	if !hasSearch {
		t.Errorf("expected a /search endpoint from the GET form; got %v", res.Endpoints)
	}
}

func TestCrawlExtractsJSEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/app.js"></script></head><body>
			<script>fetch('/api/orders?status=open')</script></body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`const u = "/api/users?id=1"; axios.get('/api/profile?uid=2');`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Crawl(context.Background(), srv.URL+"/", Options{MaxDepth: 2, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	// Endpoints referenced only in JS (inline + external app.js) must be found.
	var hasOrders, hasUsers bool
	for _, e := range res.Endpoints {
		if contains(e, "/api/orders?") {
			hasOrders = true
		}
		if contains(e, "/api/users?") {
			hasUsers = true
		}
	}
	if !hasOrders {
		t.Errorf("expected /api/orders from inline JS; got %v", res.Endpoints)
	}
	if !hasUsers {
		t.Errorf("expected /api/users from external app.js; got %v", res.Endpoints)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestCrawlBroadenedSources verifies the previously-missed sources: POST forms,
// <link>/<area>, meta-refresh, absolute URLs in JS, and sitemap.xml.
func TestCrawlBroadenedSources(t *testing.T) {
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /admin/panel\nSitemap: " + base + "/sitemap.xml\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<urlset><url><loc>` + base + `/reports?year=2026</loc></url></urlset>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head>
			<link rel="preload" href="/api/config?v=1">
			</head><body>
			<form action="/login" method="POST"><input name="user"><input name="pass"></form>
			<area href="/map?zone=3">
			<script>const api = "` + base + `/api/full?x=1"; fetch(` + "`/api/tmpl?id=9`" + `)</script>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	defer srv.Close()

	res, err := Crawl(context.Background(), srv.URL+"/", Options{MaxDepth: 2, MaxPages: 30})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/login?", "/api/config?", "/map?", "/api/full?", "/api/tmpl?", "/reports?"}
	for _, w := range want {
		found := false
		for _, e := range res.Endpoints {
			if contains(e, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected an endpoint containing %q; got %v", w, res.Endpoints)
		}
	}
}
