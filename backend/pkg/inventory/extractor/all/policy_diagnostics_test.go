package all_test

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/all"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanpolicy"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

type noAdvisories struct{}

func (noAdvisories) Match(context.Context, *inventory.Inventory) (*vulndb.Result, error) {
	return &vulndb.Result{}, nil
}

func TestParserDiagnosticsReachCIPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		exit  int
	}{
		{"malformed requirements", map[string]string{"requirements.txt": "???"}, 2},
		{"unpinned requirements", map[string]string{"requirements.txt": "requests"}, 2},
		{"empty npm lock", map[string]string{"package.json": `{"dependencies":{"lodash":"4.17.20"}}`, "package-lock.json": `{}`}, 2},
		{"missing Python lock", map[string]string{"Pipfile": "[packages]\nrequests='*'"}, 2},
		{"empty Python project", map[string]string{"requirements.txt": "# no third-party dependencies\n"}, 0},
		{"empty npm project", map[string]string{"package.json": `{}`}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, data := range tc.files {
				fsys[path] = &fstest.MapFile{Data: []byte(data)}
			}
			engine := scanner.Engine{Extractors: all.Extractors(all.Options{}), Matcher: noAdvisories{}}
			report, err := engine.Analyze(context.Background(), fsys, v1alpha1.RepositoryInfo{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := scanpolicy.New("none")
			if err != nil {
				t.Fatal(err)
			}
			decision := policy.Evaluate(report)
			if decision.ExitCode != tc.exit {
				t.Fatalf("exit=%d, want %d: %s", decision.ExitCode, tc.exit, decision.Message)
			}
			if tc.exit != 0 && len(report.Match.Warnings) == 0 {
				t.Fatal("parser diagnostic lost before CI policy")
			}
		})
	}
}
