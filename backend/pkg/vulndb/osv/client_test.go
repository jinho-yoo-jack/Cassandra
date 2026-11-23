package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQueryBatchRejectsMalformedResponses(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing results", `{}`},
		{"extra results", `{"results":[{},{}]}`},
		{"null result", `{"results":[null]}`},
		{"missing advisory id", `{"results":[{"vulns":[{}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			defer srv.Close()
			c := NewClient()
			c.APIURL = srv.URL
			got, err := c.QueryBatch(context.Background(), []Query{{Package: Package{Name: "example"}, Version: "1.0.0"}})
			if err == nil || got != nil {
				t.Fatalf("malformed response returned refs=%+v error=%v", got, err)
			}
		})
	}
}

func TestQueryBatchPagination(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Queries []Query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		if calls == 1 {
			if len(req.Queries) != 2 {
				t.Errorf("queries = %+v", req.Queries)
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"FIRST"}],"next_page_token":"next"},{"vulns":[{"id":"OTHER"}]}]}`))
			return
		}
		if len(req.Queries) != 1 || req.Queries[0].Package.Name != "first" || req.Queries[0].PageToken != "next" {
			t.Errorf("page queries = %+v", req.Queries)
		}
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"SECOND"}]}]}`))
	}))
	defer srv.Close()
	c := NewClient()
	c.APIURL = srv.URL
	qs := []Query{{Package: Package{Name: "first"}}, {Package: Package{Name: "other"}}}
	refs, err := c.QueryBatch(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(refs) != 2 || len(refs[0]) != 2 || len(refs[1]) != 1 || refs[0][1].ID != "SECOND" || refs[1][0].ID != "OTHER" || qs[0].PageToken != "" {
		t.Fatalf("pagination lost query alignment or mutated input: %+v, calls=%d queries=%+v", refs, calls, qs)
	}
}

func TestQueryBatchRejectsRepeatedPageToken(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 2 {
			http.Error(w, "test stops a pagination loop", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"next_page_token":"same"}]}`))
	}))
	defer srv.Close()
	c := NewClient()
	c.APIURL = srv.URL
	refs, err := c.QueryBatch(context.Background(), []Query{{Package: Package{Name: "example"}}})
	if refs != nil || err == nil || !strings.Contains(err.Error(), "repeated page token") || calls != 2 {
		t.Fatalf("pagination loop: refs=%+v error=%v calls=%d", refs, err, calls)
	}
}
