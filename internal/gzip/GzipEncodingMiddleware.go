package gzip

import (
	"bytes"
	"compress/gzip"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"strings"
)

var (
	gzipFilterLog = logrus.WithFields(logrus.Fields{
		"module": "GZIP Filter",
		"gofile": "GzipEncodingFilter.go",
	})
)

func NewGzipEncoderFilter(enable bool, minSizeToCompress int) *GzipEncoderFilter {
	if !enable {
		gzipFilterLog.Warnf("GZIP Compression response body is DISABLED. Should be enabled for best performance.")
	}
	return &GzipEncoderFilter{
		EnableGzip:  enable,
		GzipMinSize: minSizeToCompress,
	}
}

// GzipEncoderFilter is struct to host Middleware function DoFilter and store minimum data size for gzip
type GzipEncoderFilter struct {
	EnableGzip  bool
	GzipMinSize int
}

// DoFilter will return the middleware function for compressing body IF the client ask for Accept-Encoding: gzip
func (filter *GzipEncoderFilter) DoFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the client can accept the gzip encoding.
		if filter.EnableGzip == false || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			// The client cannot accept it, so return the output
			// uncompressed.
			gzipFilterLog.Tracef("Enable gzip is %v. Accept-Encoding is %s ", filter.EnableGzip, r.Header.Get("Accept-Encoding"))
			next.ServeHTTP(w, r)
			return
		}

		// serve the request using new recorder.
		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, r)
		bodyBytes := recorder.Body.Bytes()

		containsContentType := false

		// write the rest of the headers.
		for key, v := range recorder.Header() {
			for _, vv := range v {
				if strings.ToLower(key) == "content-type" {
					containsContentType = true
					gzipFilterLog.Tracef("%s: %s already exist.", key, vv)
				}
				w.Header().Set(key, vv)
			}
		}

		// If its non 2xx we dont compress it.
		if recorder.Code < 200 || recorder.Code >= 300 {
			// write the result.
			w.WriteHeader(recorder.Code)
			// write the body after write header so golang http will not temper to the response code
			w.Write(bodyBytes)
			return
		}

		if !containsContentType {
			ctype := http.DetectContentType(bodyBytes)
			gzipFilterLog.Tracef("Content-Type not exist. Assigning one with Content-Type: %s. ", ctype)
			w.Header().Set("Content-Type", ctype)
		}

		// if the body size is above minimum size zip them.
		if len(bodyBytes) > filter.GzipMinSize {

			// add header for gzip content encoding
			w.Header().Set("Content-Encoding", "gzip")
			// write the result.
			w.WriteHeader(recorder.Code)

			// create empty byte buffer.
			buff := bytes.NewBuffer(make([]byte, 0))

			// Create new gzip writer to write gzip result into empty buffer.
			gw := gzip.NewWriter(buff)

			// Write the original content into gzip writer.
			written, err := gw.Write(bodyBytes)
			if err != nil {
				gzipFilterLog.Errorf("Error while writing to gzip writer. got %v", err)
			}
			gw.Close()
			gzipFilterLog.Tracef("Written into gzip writer %d bytes, yielding %d bytes.", written, len(buff.Bytes()))

			// Write the gzip result into response body.
			w.Write(buff.Bytes())

		} else {
			// write the result.
			w.WriteHeader(recorder.Code)
			// if the body size is bellow minimum size to zip, return them as is.
			w.Write(bodyBytes)
		}

	})
}
