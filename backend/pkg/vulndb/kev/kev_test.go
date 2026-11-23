package kev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshValidatesFeedBeforeReplacingCatalog(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"vulnerabilities":null}`, `{"vulnerabilities":{}}`, `{"vulnerabilities":[null]}`, `{"vulnerabilities":[{}]}`, `{"vulnerabilities":[{"cveID":" "}]}`} {
		t.Run(body, func(t *testing.T) {
			current := `{"catalogVersion":"old","vulnerabilities":[{"cveID":"CVE-2024-1234"}]}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, current) }))
			defer srv.Close()
			c := NewCatalog()
			c.URL = srv.URL
			if _, _, err := c.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			current = body
			if _, _, err := c.Refresh(context.Background()); err == nil {
				t.Fatal("malformed feed accepted")
			}
			if _, ok := c.Lookup("CVE-2024-1234"); !ok || c.version != "old" {
				t.Fatal("invalid refresh replaced previous catalog")
			}
		})
	}
}

func TestRefreshAllowsEmptyCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"catalogVersion":"empty","vulnerabilities":[]}`)
	}))
	defer srv.Close()
	c := NewCatalog()
	c.URL = srv.URL
	if _, version, err := c.Refresh(context.Background()); err != nil || version != "empty" || c.Len() != 0 {
		t.Fatalf("version=%s error=%v", version, err)
	}
}
