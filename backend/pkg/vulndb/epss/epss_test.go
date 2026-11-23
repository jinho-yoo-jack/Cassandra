package epss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScoresRejectMalformedFeedWithoutCachingMiss(t *testing.T) {
	for _, body := range []string{
		`null`, `{}`, `{"data":null}`, `{"data":{}}`, `{"data":[null]}`, `{"data":[{}]}`,
		`{"data":[{"cve":" ","epss":"0.5","percentile":"0.9"}]}`,
		`{"data":[{"cve":"CVE-2024-1234","epss":"bad","percentile":"0.9"}]}`,
		`{"data":[{"cve":"CVE-2024-1234","epss":"0.5"}]}`,
		`{"data":[{"cve":"CVE-2024-1234","epss":"NaN","percentile":"0.9"}]}`,
		`{"data":[{"cve":"CVE-2024-1234","epss":"1.5","percentile":"0.9"}]}`,
		`{"data":[{"cve":"CVE-2024-1234","epss":"0.5","percentile":"-0.1"}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			current := body
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, current) }))
			defer srv.Close()
			c := NewClient()
			c.URL = srv.URL
			ids := []string{"CVE-2024-1234"}
			if got, err := c.Scores(context.Background(), ids); err == nil || len(got) != 0 {
				t.Fatalf("malformed feed returned scores=%+v error=%v", got, err)
			}
			current = `{"data":[{"cve":"CVE-2024-1234","epss":"0.5","percentile":"0.9"}]}`
			got, err := c.Scores(context.Background(), ids)
			if err != nil || got[ids[0]] == nil || got[ids[0]].Score != 0.5 || calls != 2 {
				t.Fatalf("invalid feed cached as success: scores=%+v error=%v requests=%d", got, err, calls)
			}
		})
	}
}

func TestScoresAllowsAndCachesEmptyData(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `{"data":[]}`) }))
	defer srv.Close()
	c := NewClient()
	c.URL = srv.URL
	for range 2 {
		got, err := c.Scores(context.Background(), []string{"CVE-2024-1234"})
		if err != nil || len(got) != 0 {
			t.Fatalf("scores=%+v error=%v", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("requests=%d; empty data must remain a cacheable miss", calls)
	}
}
