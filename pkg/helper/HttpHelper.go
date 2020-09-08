package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperjumptech/hansip/internal/constants"
	log "github.com/sirupsen/logrus"
)

// ResponseJSON define the structure of all response
type ResponseJSON struct {
	HTTPCode int         `json:"httpcode"`
	Message  string      `json:"message"`
	Status   string      `json:"status"`
	Data     interface{} `json:"data,omitempty"`
}

// ParsePathParams parse request path param according to path template and extract its values.
func ParsePathParams(template, path string) (map[string]string, error) {
	var pth string
	if strings.Contains(path, "?") {
		pth = path[:strings.Index(path, "?")]
	} else {
		pth = path
	}
	templatePaths := strings.Split(template, "/")
	pathPaths := strings.Split(pth, "/")
	if len(templatePaths) != len(pathPaths) {
		return nil, fmt.Errorf("pathElement length not equals to templateElement length")
	}
	ret := make(map[string]string)
	for idx, templateElement := range templatePaths {
		pathElement := pathPaths[idx]
		if len(templateElement) > 0 && len(pathElement) > 0 {
			if templateElement[:1] == "{" && templateElement[len(templateElement)-1:] == "}" {
				tKey := templateElement[1 : len(templateElement)-1]
				ret[tKey] = pathElement
			} else if templateElement != pathElement {
				return nil, fmt.Errorf("template %s not compatible with path %s", template, path)
			}
		}
	}
	return ret, nil
}

// WriteHTTPResponse into the response writer, according to the response code and headers.
// headerMap and data argument are both optional
func WriteHTTPResponse(ctx context.Context, w http.ResponseWriter, httpRespCode int, message string, headerMap map[string]string, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	if headerMap != nil {
		for k, v := range headerMap {
			w.Header().Add(k, v)
		}
	}
	if ctx.Value(constants.RequestID) != nil {
		w.Header().Add("X-Request-ID", ctx.Value(constants.RequestID).(string))
	}
	w.WriteHeader(httpRespCode)
	rJSON := &ResponseJSON{
		HTTPCode: httpRespCode,
		Message:  message,
		Data:     data,
		Status:   "FAIL",
	}
	if httpRespCode >= 200 && httpRespCode < 400 {
		rJSON.Status = "SUCCESS"
		if len(rJSON.Message) == 0 {
			rJSON.Message = "Operation Success"
		}
	} else {
		rJSON.Status = "FAIL"
		if len(rJSON.Message) == 0 {
			rJSON.Message = "Operation Failed"
		}
	}
	bytes, err := json.Marshal(rJSON)
	if err != nil {
		log.Errorf("Can not marshal. Got %s", err)
	} else {
		i, err := w.Write(bytes)
		if err != nil {
			log.Errorf("Can not write byte stream. Got %s. %d bytes written", err, i)
		}
	}
}
