package addon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/unicode"
)

type Recorder struct {
	proxy.BaseAddon
	Recorder chan string
}

var titleRegexp = regexp.MustCompile(`<title>(.*?)<\/title>`)

type Fire struct {
	Proto       string      `json:"proto"`
	Method      string      `json:"method"`
	ContentType string      `json:"content_type"`
	Title       string      `json:"title"`
	URL         string      `json:"url"`
	Header      http.Header `json:"header"`
}

func (i *Recorder) Response(f *proxy.Flow) {
	//fmt.Printf("-----> Request Method: %s, Proto: %s, URL: %s\n", f.Request.Method, f.Request.Proto, f.Request.URL)
	//s := fmt.Sprintf("Method: %s, Proto: %s, URl: %s", f.Request.Method, f.Request.Proto, f.Request.URL)

	fff := Fire{
		Proto:       f.Request.Proto,
		Method:      f.Request.Method,
		ContentType: f.Response.Header.Get("Content-Type"),
		Title:       "",
		URL:         f.Request.URL.String(),
		Header:      f.Request.Header,
	}

	contentType := f.Response.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		f.Response.ReplaceToDecodedBody()
		matches := titleRegexp.FindSubmatch(f.Response.Body)
		if len(matches) > 1 {
			title := matches[1]

			e, _, certain := charset.DetermineEncoding(f.Response.Body, contentType)
			if !certain {
				e = unicode.UTF8
			}

			var decoderTitle string

			decoder := e.NewDecoder()
			// 将原始字节流转换为 UTF-8 编码的字符串
			decodedBytes, err := decoder.Bytes(title)
			if err == nil {
				decoderTitle = string(decodedBytes)
			} else {
				decoderTitle = string(title)
			}

			fff.Title = decoderTitle
		}
	}
	fs, err := json.Marshal(fff)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	i.Recorder <- string(fs)
}
