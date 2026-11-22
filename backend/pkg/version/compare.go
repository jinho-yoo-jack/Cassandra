// Package version compares versions across ecosystems well enough to pick
// the nearest fixed version. Matching itself is delegated to OSV and NVD,
// which implement each ecosystem's exact rules.
package version

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// Compare returns -1, 0 or +1. Go and npm versions that are valid semver use
// golang.org/x/mod/semver; everything else is compared as dotted numeric
// release segments followed by a qualifier, where a pre-release qualifier
// (alpha, beta, rc, dev, ...) sorts before the release and a post-release
// qualifier (post, final, ga, release, jre, ...) sorts with or after it.
func Compare(ecosystem, a, b string) int {
	if ecosystem == "Go" || ecosystem == "npm" || ecosystem == "crates.io" {
		va, vb := canonicalSemver(a), canonicalSemver(b)
		if semver.IsValid(va) && semver.IsValid(vb) {
			return semver.Compare(va, vb)
		}
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < max(len(pa.release), len(pb.release)); i++ {
		x, y := at(pa.release, i), at(pb.release, i)
		if x != y {
			return cmp(x, y)
		}
	}
	if pa.rank != pb.rank {
		return cmp(pa.rank, pb.rank)
	}
	return compareQualifier(pa.qualifier, pb.qualifier)
}

// Less reports whether a < b.
func Less(ecosystem, a, b string) bool { return Compare(ecosystem, a, b) < 0 }

func canonicalSemver(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

type parsed struct {
	release   []int
	rank      int // -1 pre-release, 0 release, +1 post-release
	qualifier string
}

var preReleaseWords = []string{"dev", "snapshot", "alpha", "a", "beta", "b", "milestone", "m", "preview", "pre", "rc", "c", "cr"}
var postReleaseWords = []string{"post", "p", "patch", "sp", "pl"}
var neutralWords = []string{"final", "ga", "release", "jre", "android", "r"}

func parse(v string) parsed {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata never affects ordering
	}
	var p parsed
	i := 0
	for i < len(v) {
		j := i
		for j < len(v) && v[j] >= '0' && v[j] <= '9' {
			j++
		}
		if j == i {
			break
		}
		n, _ := strconv.Atoi(v[i:j])
		p.release = append(p.release, n)
		i = j
		if i < len(v) && v[i] == '.' && i+1 < len(v) && v[i+1] >= '0' && v[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	q := strings.TrimLeft(v[i:], ".-_")
	p.qualifier = q
	if q == "" {
		return p
	}
	word := strings.TrimRight(strings.FieldsFunc(q, func(r rune) bool { return r == '.' || r == '-' || r == '_' })[0], "0123456789")
	switch {
	case contains(neutralWords, word):
		p.rank, p.qualifier = 0, ""
	case contains(postReleaseWords, word):
		p.rank = 1
	case contains(preReleaseWords, word) || word != "":
		p.rank = -1
	default:
		p.rank = 1 // purely numeric suffix such as "-1" (Debian revisions)
	}
	return p
}

// compareQualifier orders qualifiers of the same rank, comparing numeric
// runs numerically ("rc10" > "rc9").
func compareQualifier(a, b string) int {
	for a != "" && b != "" {
		ia, ib := numPrefixLen(a), numPrefixLen(b)
		if ia > 0 && ib > 0 {
			x, _ := strconv.Atoi(a[:ia])
			y, _ := strconv.Atoi(b[:ib])
			if x != y {
				return cmp(x, y)
			}
			a, b = a[ia:], b[ib:]
			continue
		}
		if a[0] != b[0] {
			return cmp(a[0], b[0])
		}
		a, b = a[1:], b[1:]
	}
	return cmp(len(a), len(b))
}

func numPrefixLen(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

func at(xs []int, i int) int {
	if i < len(xs) {
		return xs[i]
	}
	return 0
}

func contains(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

func cmp[T int | byte](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
