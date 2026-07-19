package wsfuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestRun_ReflectionAndSQLi(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil { return }
		defer c.Close()
		for {
			_, data, err := c.ReadMessage()
			if err != nil { return }
			s := string(data)
			if strings.Contains(s, "'") {
				c.WriteMessage(websocket.TextMessage, []byte("You have an error in your SQL syntax; MySQL server"))
			} else {
				c.WriteMessage(websocket.TextMessage, data) // echo
			}
		}
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	f := New(wsURL, "FUZZ")
	fs, err := f.Run(context.Background())
	if err != nil { t.Fatal(err) }
	var refl, sqli bool
	for _, x := range fs {
		if x.Class == "ws-reflected-input" { refl = true }
		if x.Class == "ws-sqli" && x.Confidence == "confirmed" { sqli = true }
	}
	if !refl { t.Error("expected reflected-input finding (echo server)") }
	if !sqli { t.Error("expected confirmed ws-sqli (DB error echoed)") }
}
