package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// openOutputRoot walks pinned directory handles. Every component must be a real
// directory, and the opened inode must be the one inspected before opening.
// A checkout-controlled link (including an ancestor link swapped during open)
// therefore cannot redirect writes into another directory.
func openOutputRoot(dir string) (*os.Root, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	anchor := filepath.VolumeName(abs) + string(filepath.Separator)
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, anchor), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		info, err := root.Lstat(part)
		if os.IsNotExist(err) {
			if err = root.Mkdir(part, 0o700); err != nil && !os.IsExist(err) {
				root.Close()
				return nil, err
			}
			info, err = root.Lstat(part)
		}
		if err != nil {
			root.Close()
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, fmt.Errorf("output directory must not contain symlinks or non-directories: %s", part)
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			root.Close()
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			root.Close()
			return nil, fmt.Errorf("output directory changed while opening: %s", part)
		}
		root.Close()
		root = next
	}
	return root, nil
}

// Writes and the atomic replacement both use the pinned output handle. Neither
// intermediate directory links nor an existing destination-file link is followed.
func writeArtifact(dir, name string, data []byte) error {
	root, err := openOutputRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := ".cassandra-" + hex.EncodeToString(nonce[:])
	file, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}
