// Package all registers every extractor, like the plugin registries of
// kube-apiserver admission.
package all

import (
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/container"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/golang"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/java"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/javascript"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/php"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/python"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/ruby"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/rust"
)

// Options configures extractors that need network access.
type Options struct {
	// GoProxy resolves the Go module graph. Empty disables it.
	GoProxy string
}

// Extractors returns every extractor.
func Extractors(opts Options) []inventory.Extractor {
	return []inventory.Extractor{
		golang.New(opts.GoProxy),
		javascript.Extractor{},
		python.Extractor{},
		java.Extractor{},
		rust.Extractor{},
		ruby.Extractor{},
		php.Extractor{},
		container.Extractor{},
	}
}
