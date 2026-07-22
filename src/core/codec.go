package core

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func DecodeContent(body []byte, encoding string) []byte {
	if len(body) == 0 {
		return body
	}
	enc := strings.TrimSpace(strings.ToLower(encoding))
	if enc == "" || enc == "identity" {
		return body
	}
	if strings.Contains(enc, ",") {
		parts := strings.Split(enc, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			body = DecodeContent(body, strings.TrimSpace(parts[i]))
		}
		return body
	}
	switch enc {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		out, _ := io.ReadAll(r)
		return out
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		out, _ := io.ReadAll(r)
		return out
	case "br":
		r := brotli.NewReader(bytes.NewReader(body))
		out, _ := io.ReadAll(r)
		return out
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		out, _ := io.ReadAll(r)
		return out
	}
	return body
}
