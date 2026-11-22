package inventory

import (
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

var pypiNormalize = regexp.MustCompile(`[-_.]+`)

// NormalizePyPI applies the PEP 503 name normalisation.
func NormalizePyPI(name string) string {
	return pypiNormalize.ReplaceAllString(strings.ToLower(name), "-")
}

// splitLast splits "a/b/c" into ("a/b", "c").
func splitLast(name, sep string) (string, string) {
	i := strings.LastIndex(name, sep)
	if i < 0 {
		return "", name
	}
	return name[:i], name[i+1:]
}

// PURL builds the package URL of a component.
func PURL(eco Ecosystem, name, version string) string {
	var ns string
	typ := packageurl.TypeGeneric
	switch eco {
	case Go:
		typ = packageurl.TypeGolang
		ns, name = splitLast(name, "/")
	case NPM:
		typ = packageurl.TypeNPM
		if strings.HasPrefix(name, "@") {
			ns, name = splitLast(name, "/")
		}
	case PyPI:
		typ = packageurl.TypePyPi
		name = NormalizePyPI(name)
	case Maven:
		typ = packageurl.TypeMaven
		ns, name = splitLast(name, ":")
	case CratesIO:
		typ = packageurl.TypeCargo
	case RubyGems:
		typ = packageurl.TypeGem
	case Packagist:
		typ = packageurl.TypeComposer
		ns, name = splitLast(name, "/")
	case Image:
		typ = packageurl.TypeDocker
		ns, name = splitLast(name, "/")
	}
	return packageurl.NewPackageURL(typ, ns, name, version, nil, "").ToString()
}

// NewLibrary returns a library component with ID and PURL filled in.
func NewLibrary(eco Ecosystem, name, version, location string, direct, dev bool) *Component {
	purl := PURL(eco, name, version)
	return &Component{
		ID: purl, PURL: purl, Type: TypeLibrary,
		Name: name, Version: version, Ecosystem: eco,
		Direct: direct, Dev: dev, Locations: []string{location},
	}
}

var leadingVersion = regexp.MustCompile(`\d+(\.\d+){0,3}([-.+]?[0-9A-Za-z.]+)?`)

// VersionFromRange extracts a concrete version from a range such as "^1.2.3"
// or ">=2.0,<3". Used only when no lockfile pins the version, so results are
// marked approximate by the caller.
func VersionFromRange(r string) string {
	r = strings.TrimSpace(r)
	if r == "" || r == "*" || r == "latest" {
		return ""
	}
	if i := strings.IndexAny(r, ",|"); i >= 0 {
		r = r[:i]
	}
	return leadingVersion.FindString(r)
}
