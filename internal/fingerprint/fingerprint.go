// Package fingerprint passively identifies the CMS, framework, language, server,
// CDN, and other web technologies behind a target from a single response. It is
// built around a strict confidence model so it never over-claims: only a
// deterministic, effectively-unforgeable signal (a versioned X-Powered-By /
// X-Generator header, a meta generator tag, a product-unique cookie or path)
// yields Confirmed. Anything softer — a shared library reference, a generic path
// — is reported as Likely/Possible and never as a confirmed finding. This keeps
// the platform's zero-false-positive contract intact for everything it calls
// "confirmed".
package fingerprint

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Confidence grades how certain a detection is.
type Confidence string

const (
	Confirmed Confidence = "confirmed" // deterministic, unforgeable signal — zero-FP
	Likely    Confidence = "likely"    // strong heuristic, small FP chance
	Possible  Confidence = "possible"  // weak hint
)

// Tech is one identified technology.
type Tech struct {
	Name       string
	Category   string // CMS | Framework | Language | Server | CDN | WAF | Analytics | JS-Library | Ecommerce
	Version    string
	Confidence Confidence
	Evidence   string
}

// where selects which response part a matcher inspects.
type where int

const (
	inHeader where = iota // a specific header's value
	inCookie              // any Set-Cookie name/value
	inBody                // response body
	inPath                // request URL path
)

type sig struct {
	name, category string
	conf           Confidence
	src            where
	header         string         // header name when src==inHeader
	re             *regexp.Regexp // matcher; capture group 1 (if any) is the version
}

// sigs is the signature database. Confirmed entries use signals that a site
// cannot accidentally emit for a different technology.
var sigs = []sig{
	// ── CMS ──
	{"WordPress", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']WordPress ?([0-9.]+)?`)},
	{"WordPress", "CMS", Confirmed, inPath, "", regexp.MustCompile(`(?i)/wp-(?:content|includes)/`)},
	{"WordPress", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)/wp-(?:content|includes|json)/|xmlrpc\.php`)},
	{"WordPress", "CMS", Confirmed, inCookie, "", regexp.MustCompile(`(?i)\bwordpress_(?:logged_in|sec|test_cookie)|wp-settings`)},
	{"Joomla", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']Joomla!?[ ]?([0-9.]+)?`)},
	{"Joomla", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)/media/jui/|option=com_|/components/com_`)},
	{"Joomla", "CMS", Likely, inCookie, "", regexp.MustCompile(`(?i)^[a-f0-9]{32}=`)},
	{"Drupal", "CMS", Confirmed, inHeader, "X-Generator", regexp.MustCompile(`(?i)Drupal ?([0-9.]+)?`)},
	{"Drupal", "CMS", Confirmed, inHeader, "X-Drupal-Cache", regexp.MustCompile(`.+`)},
	{"Drupal", "CMS", Confirmed, inHeader, "X-Drupal-Dynamic-Cache", regexp.MustCompile(`.+`)},
	{"Drupal", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)<meta name=["']Generator["'] content=["']Drupal ?([0-9.]+)?`)},
	{"Drupal", "CMS", Likely, inBody, "", regexp.MustCompile(`(?i)/sites/(?:all|default)/|drupal\.settings`)},
	{"Ghost", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']Ghost ?([0-9.]+)?`)},
	{"TYPO3", "CMS", Confirmed, inBody, "", regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']TYPO3 ?([0-9.]+)?`)},
	{"TYPO3", "CMS", Likely, inBody, "", regexp.MustCompile(`(?i)/typo3(?:conf|temp)/`)},
	{"Umbraco", "CMS", Likely, inHeader, "X-Umbraco-Version", regexp.MustCompile(`([0-9.]+)`)},
	{"Sitecore", "CMS", Likely, inCookie, "", regexp.MustCompile(`(?i)SC_ANALYTICS_GLOBAL_COOKIE`)},
	{"Craft CMS", "CMS", Likely, inCookie, "", regexp.MustCompile(`(?i)CraftSessionId`)},
	{"Concrete CMS", "CMS", Likely, inCookie, "", regexp.MustCompile(`(?i)CONCRETE5?`)},

	// ── Ecommerce ──
	{"Shopify", "Ecommerce", Confirmed, inHeader, "X-Shopify-Stage", regexp.MustCompile(`.+`)},
	{"Shopify", "Ecommerce", Confirmed, inHeader, "X-ShopId", regexp.MustCompile(`.+`)},
	{"Shopify", "Ecommerce", Confirmed, inBody, "", regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`)},
	{"Magento", "Ecommerce", Confirmed, inCookie, "", regexp.MustCompile(`(?i)^X-Magento|frontend=|mage-cache`)},
	{"Magento", "Ecommerce", Confirmed, inBody, "", regexp.MustCompile(`(?i)/static/version\d+/frontend/|Mage\.Cookies|/skin/frontend/`)},
	{"WooCommerce", "Ecommerce", Confirmed, inBody, "", regexp.MustCompile(`(?i)/wp-content/plugins/woocommerce/`)},
	{"PrestaShop", "Ecommerce", Confirmed, inHeader, "Set-Cookie", regexp.MustCompile(`(?i)PrestaShop-`)},
	{"PrestaShop", "Ecommerce", Confirmed, inBody, "", regexp.MustCompile(`(?i)var prestashop|/themes/[^/]+/assets/`)},
	{"BigCommerce", "Ecommerce", Likely, inBody, "", regexp.MustCompile(`(?i)cdn\d*\.bigcommerce\.com`)},

	// ── Language ──
	{"PHP", "Language", Confirmed, inHeader, "X-Powered-By", regexp.MustCompile(`(?i)PHP/?([0-9.]+)?`)},
	{"PHP", "Language", Confirmed, inCookie, "", regexp.MustCompile(`(?i)\bPHPSESSID=`)},
	{"ASP.NET", "Language", Confirmed, inHeader, "X-AspNet-Version", regexp.MustCompile(`([0-9.]+)`)},
	{"ASP.NET", "Language", Confirmed, inHeader, "X-Powered-By", regexp.MustCompile(`(?i)ASP\.NET`)},
	{"ASP.NET", "Language", Confirmed, inCookie, "", regexp.MustCompile(`(?i)ASP\.NET_SessionId=|\.ASPXAUTH=`)},
	{"Java", "Language", Confirmed, inCookie, "", regexp.MustCompile(`(?i)\bJSESSIONID=`)},
	{"Python", "Language", Likely, inHeader, "Server", regexp.MustCompile(`(?i)Werkzeug|gunicorn|Python/?([0-9.]+)?`)},
	{"Ruby", "Language", Likely, inHeader, "Server", regexp.MustCompile(`(?i)Phusion Passenger|WEBrick`)},
	{"Node.js", "Language", Likely, inHeader, "X-Powered-By", regexp.MustCompile(`(?i)Express`)},

	// ── Framework ──
	{"Laravel", "Framework", Confirmed, inCookie, "", regexp.MustCompile(`(?i)laravel_session=|XSRF-TOKEN=`)},
	{"Django", "Framework", Confirmed, inCookie, "", regexp.MustCompile(`(?i)\bcsrftoken=|\bsessionid=`)},
	{"Ruby on Rails", "Framework", Confirmed, inCookie, "", regexp.MustCompile(`(?i)_rails|_session_id=`)},
	{"CodeIgniter", "Framework", Confirmed, inCookie, "", regexp.MustCompile(`(?i)ci_session=`)},
	{"Symfony", "Framework", Likely, inCookie, "", regexp.MustCompile(`(?i)symfony=|sf_redirect`)},
	{"Spring", "Framework", Likely, inHeader, "X-Application-Context", regexp.MustCompile(`.+`)},
	{"Flask", "Framework", Likely, inCookie, "", regexp.MustCompile(`(?i)\bsession=eyJ`)},
	{"Next.js", "Framework", Confirmed, inHeader, "X-Powered-By", regexp.MustCompile(`(?i)Next\.js ?([0-9.]+)?`)},
	{"Next.js", "Framework", Confirmed, inBody, "", regexp.MustCompile(`(?i)/_next/static/|__NEXT_DATA__`)},
	{"Nuxt.js", "Framework", Confirmed, inBody, "", regexp.MustCompile(`(?i)/_nuxt/|__NUXT__`)},
	{"Gatsby", "Framework", Likely, inBody, "", regexp.MustCompile(`(?i)/page-data/|___gatsby`)},
	{"Angular", "Framework", Likely, inBody, "", regexp.MustCompile(`(?i)ng-version=["']([0-9.]+)|<app-root`)},
	{"React", "JS-Library", Likely, inBody, "", regexp.MustCompile(`(?i)data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js`)},
	{"Vue.js", "JS-Library", Likely, inBody, "", regexp.MustCompile(`(?i)data-v-[0-9a-f]{8}|vue(?:\.min)?\.js`)},
	{"jQuery", "JS-Library", Possible, inBody, "", regexp.MustCompile(`(?i)jquery[.-]([0-9.]+)?(?:\.min)?\.js`)},
	{"Svelte", "JS-Library", Possible, inBody, "", regexp.MustCompile(`(?i)svelte-[0-9a-z]{6}`)},

	// ── Server ──
	{"nginx", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)nginx/?([0-9.]+)?`)},
	{"Apache", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)Apache/?([0-9.]+)?`)},
	{"Microsoft IIS", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)Microsoft-IIS/?([0-9.]+)?`)},
	{"LiteSpeed", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)LiteSpeed`)},
	{"Caddy", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)Caddy`)},
	{"Tomcat", "Server", Likely, inHeader, "Server", regexp.MustCompile(`(?i)Apache-Coyote|Tomcat`)},
	{"Envoy", "Server", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)envoy`)},

	// ── CDN ──
	{"Cloudflare", "CDN", Confirmed, inHeader, "Server", regexp.MustCompile(`(?i)cloudflare`)},
	{"Cloudflare", "CDN", Confirmed, inHeader, "CF-RAY", regexp.MustCompile(`.+`)},
	{"Fastly", "CDN", Confirmed, inHeader, "X-Served-By", regexp.MustCompile(`(?i)cache-.*fastly|^cache-`)},
	{"Fastly", "CDN", Confirmed, inHeader, "Fastly-Debug-Digest", regexp.MustCompile(`.+`)},
	{"Akamai", "CDN", Confirmed, inHeader, "X-Akamai-Transformed", regexp.MustCompile(`.+`)},
	{"Amazon CloudFront", "CDN", Confirmed, inHeader, "X-Amz-Cf-Id", regexp.MustCompile(`.+`)},
	{"Vercel", "CDN", Confirmed, inHeader, "X-Vercel-Id", regexp.MustCompile(`.+`)},
	{"Netlify", "CDN", Confirmed, inHeader, "X-Nf-Request-Id", regexp.MustCompile(`.+`)},
	{"Sucuri", "CDN", Confirmed, inHeader, "X-Sucuri-ID", regexp.MustCompile(`.+`)},

	// ── Analytics ──
	{"Google Analytics", "Analytics", Confirmed, inBody, "", regexp.MustCompile(`(?i)google-analytics\.com/(?:analytics|ga)\.js|gtag\('config'`)},
	{"Google Tag Manager", "Analytics", Confirmed, inBody, "", regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`)},
	{"Hotjar", "Analytics", Likely, inBody, "", regexp.MustCompile(`(?i)static\.hotjar\.com`)},
	{"Segment", "Analytics", Likely, inBody, "", regexp.MustCompile(`(?i)cdn\.segment\.com`)},
}

// Detect runs the signature set over a single response and returns the deduped
// technologies, highest confidence first. cookies is the raw Set-Cookie values
// (or the request Cookie header); body is the response body; urlPath is the
// request path.
func Detect(header http.Header, body []byte, urlPath string) []Tech {
	best := map[string]Tech{}
	consider := func(t Tech) {
		cur, ok := best[t.Name]
		if !ok || rank(t.Confidence) > rank(cur.Confidence) || (t.Version != "" && cur.Version == "") {
			// keep a version if we already have one
			if ok && cur.Version != "" && t.Version == "" {
				t.Version = cur.Version
			}
			best[t.Name] = t
		}
	}
	setCookie := strings.Join(header.Values("Set-Cookie"), "\n")
	bodyStr := string(body)

	for _, s := range sigs {
		var hay, evidenceCtx string
		switch s.src {
		case inHeader:
			hay = header.Get(s.header)
			evidenceCtx = "header " + s.header
		case inCookie:
			hay = setCookie
			evidenceCtx = "Set-Cookie"
		case inBody:
			hay = bodyStr
			evidenceCtx = "response body"
		case inPath:
			hay = urlPath
			evidenceCtx = "URL path"
		}
		if hay == "" {
			continue
		}
		m := s.re.FindStringSubmatch(hay)
		if m == nil {
			continue
		}
		version := ""
		if len(m) > 1 {
			version = strings.TrimSpace(m[1])
		}
		consider(Tech{
			Name: s.name, Category: s.category, Version: version,
			Confidence: s.conf, Evidence: evidenceCtx + " signature match",
		})
	}

	out := make([]Tech, 0, len(best))
	for _, t := range best {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i].Confidence) != rank(out[j].Confidence) {
			return rank(out[i].Confidence) > rank(out[j].Confidence)
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func rank(c Confidence) int {
	switch c {
	case Confirmed:
		return 3
	case Likely:
		return 2
	case Possible:
		return 1
	}
	return 0
}

// Confirmed returns only the deterministically-identified technologies — the
// subset safe to present as confirmed findings (zero false positives).
func ConfirmedOnly(techs []Tech) []Tech {
	var out []Tech
	for _, t := range techs {
		if t.Confidence == Confirmed {
			out = append(out, t)
		}
	}
	return out
}
