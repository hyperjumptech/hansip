package api

import "net/http"

func NewStaticFilter() *StaticFilter {
	resMap, mimMap := GetStaticResource()
	ret := &StaticFilter{
		StaticResources: resMap,
		MimeTypes:       mimMap,
	}
	return ret
}

type StaticFilter struct {
	StaticResources map[string][]byte
	MimeTypes       map[string]string
}

func (filter *StaticFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/docs" || r.URL.Path == "/docs/" {
		http.Redirect(w, r, "/docs/index.html", 301)
	} else {
		if binary, ok := filter.StaticResources[r.URL.Path]; ok {
			w.Header().Add("Content-Type", filter.MimeTypes[r.URL.Path])
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(binary)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}
