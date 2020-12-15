package api

import (
	"fmt"
	"github.com/hyperjumptech/hansip/internal/config"
	"net/http"
	"strings"
)

var (
	apiPrefix = config.Get("api.path.prefix")

	StaticResources map[string][]byte
	MimeTypes       map[string]string
)

func init() {
	resMap, mimMap := GetStaticResource()
	StaticResources = resMap
	MimeTypes = mimMap
}

func ServeStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/docs" || r.URL.Path == "/docs/" {
		http.Redirect(w, r, "/docs/index.html", 301)
	} else {
		if binary, ok := StaticResources[r.URL.Path]; ok {
			if r.URL.Path == "/docs/spec/hansip-api.json" {
				data := strings.ReplaceAll(string(binary), `"basePath": "/api/v1/",`, fmt.Sprintf(`"basePath": "%s",`, apiPrefix))
				w.Header().Add("Content-Type", MimeTypes[r.URL.Path])
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(data))
			} else if r.URL.Path == "/docs/spec/hansip-api.yml" {
				data := strings.ReplaceAll(string(binary), `basePath: "/api/v1/"`, fmt.Sprintf(`basePath: "%s"`, apiPrefix))
				w.Header().Add("Content-Type", MimeTypes[r.URL.Path])
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(data))
			} else {
				w.Header().Add("Content-Type", MimeTypes[r.URL.Path])
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(binary)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}
