// Package field reports validation errors against field paths, modelled after
// k8s.io/apimachinery/pkg/util/validation/field.
package field

import (
	"fmt"
	"strings"
)

// Path is a dotted path to a field, e.g. spec.repositoryURL.
type Path struct {
	parent *Path
	name   string
}

// NewPath creates a root path.
func NewPath(name string, more ...string) *Path {
	p := &Path{name: name}
	for _, m := range more {
		p = p.Child(m)
	}
	return p
}

// Child returns a sub-path.
func (p *Path) Child(name string) *Path { return &Path{parent: p, name: name} }

// String renders the path.
func (p *Path) String() string {
	var elems []string
	for cur := p; cur != nil; cur = cur.parent {
		elems = append(elems, cur.name)
	}
	for i, j := 0, len(elems)-1; i < j; i, j = i+1, j-1 {
		elems[i], elems[j] = elems[j], elems[i]
	}
	return strings.Join(elems, ".")
}

// Error is a single field validation error.
type Error struct {
	Field  string
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Detail) }

// ErrorList is a list of field errors.
type ErrorList []*Error

// Required reports a missing required field.
func Required(p *Path, detail string) *Error {
	if detail == "" {
		detail = "Required value"
	}
	return &Error{Field: p.String(), Detail: detail}
}

// Invalid reports an invalid value.
func Invalid(p *Path, value any, detail string) *Error {
	return &Error{Field: p.String(), Detail: fmt.Sprintf("Invalid value %q: %s", fmt.Sprint(value), detail)}
}

// Forbidden reports a field that may not be set.
func Forbidden(p *Path, detail string) *Error {
	return &Error{Field: p.String(), Detail: "Forbidden: " + detail}
}
