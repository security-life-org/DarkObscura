package engine

import (
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"sync"
)

// Session maintains state across requests to one target: a cookie jar plus
// extracted anti-CSRF tokens. It is the mechanism that makes DarkObscura's
// fuzzing stateful rather than stateless.
type Session struct {
	Client *http.Client

	mu       sync.RWMutex
	csrf     map[string]string // token name -> latest value
	csrfPats []*regexp.Regexp
}

// csrfPatterns match common CSRF token representations in HTML/JSON bodies.
var csrfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)name=["'](csrf[_-]?token|authenticity_token|__requestverificationtoken)["']\s+value=["']([^"']+)["']`),
	regexp.MustCompile(`(?i)["'](csrf[_-]?token|xsrf[_-]?token)["']\s*:\s*["']([^"']+)["']`),
}

// NewSession creates a session with its own cookie jar.
func NewSession() (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Session{
		Client:   &http.Client{Jar: jar},
		csrf:     make(map[string]string),
		csrfPats: csrfPatterns,
	}, nil
}

// Observe scans a response body for CSRF tokens and records them for reuse.
func (s *Session) Observe(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, re := range s.csrfPats {
		for _, m := range re.FindAllSubmatch(body, -1) {
			if len(m) == 3 {
				s.csrf[string(m[1])] = string(m[2])
			}
		}
	}
}

// Token returns the most recently observed value for a CSRF token name.
func (s *Session) Token(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.csrf[name]
	return v, ok
}

// Tokens returns a copy of all observed CSRF tokens.
func (s *Session) Tokens() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.csrf))
	for k, v := range s.csrf {
		out[k] = v
	}
	return out
}
