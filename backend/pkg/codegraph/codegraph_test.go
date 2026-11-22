package codegraph

import (
	"context"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory/extractor/all"
)

func TestBuild(t *testing.T) {
	repo := fstest.MapFS{
		"go.mod":                   {Data: []byte("module example.com/app\n\ngo 1.23.0\n\nrequire github.com/gin-gonic/gin v1.9.0\n")},
		"cmd/main.go":              {Data: []byte("package main\nimport (\n\t\"fmt\"\n\t\"example.com/app/internal/api\"\n)\nfunc main(){fmt.Println(api.X)}\n")},
		"internal/api/api.go":      {Data: []byte("package api\nimport \"github.com/gin-gonic/gin/binding\"\nvar X = binding.JSON\n")},
		"web/package.json":         {Data: []byte(`{"name":"web","dependencies":{"@tanstack/react-query":"5.0.0","axios":"1.6.0"}}`)},
		"web/src/App.tsx":          {Data: []byte("import { useQuery } from '@tanstack/react-query'\nimport { api } from './lib/api'\n")},
		"web/src/lib/api.ts":       {Data: []byte("const axios = require('axios')\nimport fs from 'node:fs'\n")},
		"svc/requirements.txt":     {Data: []byte("PyYAML==6.0\nrequests==2.31.0\n")},
		"svc/app/main.py":          {Data: []byte("import yaml, requests\nfrom .util import helper\nfrom app.util import other\n")},
		"svc/app/util/__init__.py": {Data: []byte("")},
	}
	ctx := context.Background()
	inv, err := inventory.Extract(ctx, repo, all.Extractors(all.Options{}), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	g, err := Build(ctx, repo, inv, DefaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	have := map[Edge]bool{}
	for _, e := range g.Edges {
		have[e] = true
	}
	want := []Edge{
		{From: "package:cmd", To: "package:internal/api"},
		{From: "package:cmd", To: "pkg:golang/stdlib@1.23.0"},
		{From: "package:internal/api", To: "pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
		{From: "package:web/src", To: "pkg:npm/%40tanstack/react-query@5.0.0"},
		{From: "package:web/src", To: "package:web/src/lib"},
		{From: "package:web/src/lib", To: "pkg:npm/axios@1.6.0"},
		{From: "package:svc/app", To: "pkg:pypi/pyyaml@6.0"},
		{From: "package:svc/app", To: "pkg:pypi/requests@2.31.0"},
		{From: "package:svc/app", To: "package:svc/app/util"},
	}
	for _, e := range want {
		if !have[e] {
			t.Errorf("missing edge %s -> %s", e.From, e.To)
		}
	}
	for _, p := range g.Packages {
		if p.Project == "" {
			t.Errorf("package %s has no owning project", p.Dir)
		}
	}
	if len(inv.Projects) == 0 || inv.Projects[0].ID > inv.Projects[len(inv.Projects)-1].ID {
		t.Errorf("Build reordered inventory projects")
	}
}

func TestCollapse(t *testing.T) {
	g := &Graph{
		Packages: []*Package{{ID: "package:a/b/c", Dir: "a/b/c", Files: 1}, {ID: "package:a/b/d", Dir: "a/b/d", Files: 2}, {ID: "package:a/e", Dir: "a/e", Files: 1}},
		Edges:    []Edge{{From: "package:a/b/c", To: "package:a/b/d"}, {From: "package:a/b/c", To: "package:a/e"}},
	}
	collapse(g, 2)
	if len(g.Packages) != 2 {
		t.Fatalf("got %d packages, want 2", len(g.Packages))
	}
	if len(g.Edges) != 1 || g.Edges[0] != (Edge{From: "package:a/b", To: "package:a/e"}) {
		t.Errorf("edges = %v", g.Edges)
	}
}
