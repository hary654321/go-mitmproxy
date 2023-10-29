package addon

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/models"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
)

type Recorder struct {
	proxy.BaseAddon
	Recorder chan string
}

var titleRegexp = regexp.MustCompile(`<title>(.*?)<\/title>`)

func (i *Recorder) Response(f *proxy.Flow) {
	//fmt.Printf("-----> Request Method: %s, Proto: %s, URL: %s\n", f.Request.Method, f.Request.Proto, f.Request.URL)
	//s := fmt.Sprintf("Method: %s, Proto: %s, URl: %s", f.Request.Method, f.Request.Proto, f.Request.URL)

	header, _ := json.Marshal(f.Request.Header)

	bh := models.Bh{
		// Proto:       f.Request.Proto,
		// Method:      f.Request.Method,
		// ContentType: f.Response.Header.Get("Content-Type"),
		// URL:         f.Request.URL.String(),
		Host:   f.Request.URL.Host,
		Scheme: f.Request.URL.Scheme,
		// Path:   f.Request.URL.Path,
		Header: string(header),
		Ctime:  time.Now().Unix(),
	}

	models.AddBh(bh)
}
