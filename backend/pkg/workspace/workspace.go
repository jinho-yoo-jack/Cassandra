// Package workspace decides where working copies live on disk.
package workspace

import "path/filepath"

// Layout is the on-disk layout below the data directory.
type Layout struct {
	Root string
}

// Scans is the parent of scan working copies.
func (l Layout) Scans() string { return filepath.Join(l.Root, "workspaces") }

// Remediation is the working copy of a remediation.
func (l Layout) Remediation(name string) string {
	return filepath.Join(l.Root, "workspaces", "remediations", name)
}
