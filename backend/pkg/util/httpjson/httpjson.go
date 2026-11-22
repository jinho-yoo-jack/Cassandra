// Package httpjson performs JSON HTTP requests with bounded response sizes.
package httpjson

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// MaxResponseBytes bounds decoded responses.
const MaxResponseBytes = 64 << 20

// StatusError is returned for non-2xx responses.
type StatusError struct {
	URL  string
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d: %s", e.URL, e.Code, e.Body)
}

// IsNotFound reports whether err is an HTTP 404.
func IsNotFound(err error) bool {
	se, ok := err.(*StatusError)
	return ok && se.Code == http.StatusNotFound
}

// Do sends a request with an optional JSON body and decodes the JSON response
// into out.
func Do(ctx context.Context, c *http.Client, method, url string, header http.Header, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{URL: url, Code: resp.StatusCode, Body: string(bytes.TrimSpace(msg))}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, MaxResponseBytes)).Decode(out)
}

// Get is Do with GET and no body.
func Get(ctx context.Context, c *http.Client, url string, header http.Header, out any) error {
	return Do(ctx, c, http.MethodGet, url, header, nil, out)
}
