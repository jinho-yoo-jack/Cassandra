// Package feeds keeps the local advisory cache in sync with upstream
// sources and tells the scan controller which stored scans may be affected.
package feeds

import (
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// PackageKey identifies a package across scans: an OSV ecosystem and name,
// or "CPE" and vendor:product for processes.
type PackageKey struct {
	Ecosystem string
	Name      string
}

// String renders the key.
func (k PackageKey) String() string { return k.Ecosystem + "/" + k.Name }

// NewPackageKey normalises names the way OSV does for each ecosystem.
func NewPackageKey(ecosystem, name string) PackageKey {
	if ecosystem == string(inventory.PyPI) {
		name = inventory.NormalizePyPI(name)
	}
	return PackageKey{Ecosystem: ecosystem, Name: name}
}

// KeysOf returns the keys under which a component can be affected.
func KeysOf(c *inventory.Component) []PackageKey {
	if c.Ecosystem == inventory.Process {
		keys := make([]PackageKey, 0, len(c.CPEs))
		for _, cpe := range c.CPEs {
			keys = append(keys, PackageKey{Ecosystem: "CPE", Name: cpe})
		}
		return keys
	}
	if c.Ecosystem == inventory.Image {
		return nil
	}
	return []PackageKey{NewPackageKey(string(c.Ecosystem), c.Name)}
}

// Changes describes what a sync observed.
type Changes struct {
	Packages []PackageKey
	// CVEs whose metadata (KEV listing) changed.
	CVEs []string
}

// Empty reports whether there is nothing to act on.
func (c Changes) Empty() bool { return len(c.Packages) == 0 && len(c.CVEs) == 0 }

// Sink receives changes; the scan controller implements it.
type Sink interface {
	// Notify returns the number of scans scheduled for re-evaluation.
	Notify(Changes) int
}

func normalizeEcosystem(e string) string {
	// OSV ecosystems may carry a release suffix, e.g. "Debian:12".
	base, _, _ := strings.Cut(e, ":")
	return base
}
