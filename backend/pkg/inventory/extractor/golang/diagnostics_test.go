package golang

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

func TestProxyFallbackDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		warn   bool
	}{
		{"unavailable", 404, "not found", true},
		{"malformed", 200, "???", true},
		{"empty response", 200, "", true},
		{"valid", 200, "module example.com/lib\ngo 1.23\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer proxy.Close()
			fsys := fstest.MapFS{"go.mod": {Data: []byte("module example.com/app\ngo 1.23\nrequire example.com/lib v1.2.3\n")}}
			inv, warnings, err := inventory.ExtractWithDiagnostics(context.Background(), fsys, []inventory.Extractor{New(proxy.URL)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if (len(warnings) > 0) != tc.warn {
				t.Errorf("warnings=%v, want warning=%v", warnings, tc.warn)
			}
			if tc.warn && len(warnings) > 0 && !strings.Contains(warnings[0], "example.com/lib") {
				t.Errorf("missing module context: %v", warnings)
			}
			if inv.Component("pkg:golang/example.com/lib@v1.2.3") == nil {
				t.Fatal("fallback discarded resolved module")
			}
		})
	}
}
