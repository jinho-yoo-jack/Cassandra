package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
)

func TestPaginationRejectsIncompleteResponses(t *testing.T) {
	validFirst := `{"startIndex":0,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`
	for _, tc := range []struct {
		name  string
		pages []string
	}{
		{"null", []string{`null`}},
		{"empty object", []string{`{}`}},
		{"missing total", []string{`{"startIndex":0,"resultsPerPage":0,"vulnerabilities":[]}`}},
		{"missing start", []string{`{"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}`}},
		{"missing count", []string{`{"startIndex":0,"totalResults":0,"vulnerabilities":[]}`}},
		{"missing array", []string{`{"startIndex":0,"resultsPerPage":0,"totalResults":0}`}},
		{"null array", []string{`{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":null}`}},
		{"empty incomplete", []string{`{"startIndex":0,"resultsPerPage":0,"totalResults":1,"vulnerabilities":[]}`}},
		{"wrong start", []string{`{"startIndex":1,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}`}},
		{"negative total", []string{`{"startIndex":0,"resultsPerPage":0,"totalResults":-1,"vulnerabilities":[]}`}},
		{"short page", []string{`{"startIndex":0,"resultsPerPage":2,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`}},
		{"more than total", []string{`{"startIndex":0,"resultsPerPage":1,"totalResults":0,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`}},
		{"missing cve", []string{`{"startIndex":0,"resultsPerPage":1,"totalResults":1,"vulnerabilities":[{}]}`}},
		{"missing id", []string{`{"startIndex":0,"resultsPerPage":1,"totalResults":1,"vulnerabilities":[{"cve":{}}]}`}},
		{"truncated second page", []string{validFirst, `{"startIndex":1,"resultsPerPage":0,"totalResults":2,"vulnerabilities":[]}`}},
		{"repeated first page", []string{validFirst, validFirst}},
		{"changed total", []string{validFirst, `{"startIndex":1,"resultsPerPage":0,"totalResults":1,"vulnerabilities":[]}`}},
		{"duplicate cve", []string{validFirst, `{"startIndex":1,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := pageClient(t, tc.pages)
			got, err := c.CVEsByCPE(context.Background(), CPEName("f5:nginx", "1.25.3"))
			if err == nil || got != nil {
				t.Fatalf("records=%+v error=%v; incomplete response must fail without partial results", got, err)
			}
		})
	}
}

func TestPaginationAcceptsCompleteResponses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pages []string
		count int
	}{
		{"empty", []string{`{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}`}, 0},
		{"two pages", []string{
			`{"startIndex":0,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`,
			`{"startIndex":1,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1235"}}]}`,
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := pageClient(t, tc.pages)
			got, err := c.CVEsByCPE(context.Background(), CPEName("f5:nginx", "1.25.3"))
			if err != nil || len(got) != tc.count {
				t.Fatalf("records=%+v error=%v", got, err)
			}
		})
	}
}

func TestModifiedBetweenRejectsIncompletePage(t *testing.T) {
	c := pageClient(t, []string{`{"startIndex":0,"resultsPerPage":2,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`})
	calls := 0
	_, err := c.paginate(context.Background(), "", func(CVE) error { calls++; return nil })
	if err == nil || calls != 0 {
		t.Fatalf("error=%v callbacks=%d; invalid page must not stream", err, calls)
	}
}

func pageClient(t *testing.T, pages []string) *Client {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls >= len(pages) {
			t.Error("unexpected extra page")
			http.Error(w, "extra page", 500)
			return
		}
		fmt.Fprint(w, pages[calls])
		calls++
	}))
	t.Cleanup(srv.Close)
	c := NewClient("")
	c.URL, c.HTTP, c.limiter = srv.URL, srv.Client(), rate.NewLimiter(rate.Inf, 1)
	return c
}
