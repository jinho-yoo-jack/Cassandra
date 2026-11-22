package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// spaHandler serves a built single page application: existing files are
// served as is, every other path falls back to index.html so client-side
// routes work on reload.
func spaHandler(dir string) http.Handler {
	fileServer := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/apis/") {
			http.NotFound(w, r)
			return
		}
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}
