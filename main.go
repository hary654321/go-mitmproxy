package main

import (
	"fmt"
	rawLog "log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/lqqyt2423/go-mitmproxy/addon"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/config"
	"github.com/lqqyt2423/go-mitmproxy/models"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/web"
	log "github.com/sirupsen/logrus"
)

func main() {
	config.NewConfig("config.yaml")
	config := config.LoadConfig()

	models.Setup()
	if config.Debug > 0 {
		rawLog.SetFlags(rawLog.LstdFlags | rawLog.Lshortfile)
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetLevel(log.ErrorLevel)
	if config.Debug == 2 {
		log.SetReportCaller(true)
	}
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	// 将证书路径设置为当前目录
	config.CertPath = "certs"

	opts := &proxy.Options{
		Debug:             config.Debug,
		Addr:              config.Addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.SslInsecure,
		CaRootPath:        config.CertPath,
		Upstream:          config.Upstream,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if config.Version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	log.Infof("go-mitmproxy version %v\n", p.Version)

	if len(config.IgnoreHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return !matchHost(req.Host, config.IgnoreHosts)
		})
	}
	if len(config.AllowHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return matchHost(req.Host, config.AllowHosts)
		})
	}

	// 安装证书
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("get current dir error: %v", err)
	}
	certPath := filepath.Join(currentDir, config.CertPath, "mitmproxy-ca-cert.cer")
	ok, err := cert.InstallCert(certPath)
	if ok {
		log.Infof("install cert success")
	} else {
		log.Infof("install cert failed: %v", err)
	}

	p.AddAddon(&proxy.LogAddon{})
	p.AddAddon(web.NewWebAddon(config.WebAddr))

	recordChan := make(chan string, 1000)
	defer close(recordChan)

	// go WriteRecord(config.RecordDir, recordChan)
	p.AddAddon(&addon.Recorder{Recorder: recordChan})
	// 设置系统代理
	err = gosysproxy.SetGlobalProxy("127.0.0.1:9080")
	if err != nil {
		log.Fatalf("set global proxy error: %v", err)
	}
	defer gosysproxy.Off()

	if config.MapRemote != "" {
		mapRemote, err := addon.NewMapRemoteFromFile(config.MapRemote)
		if err != nil {
			log.Warnf("load map remote error: %v", err)
		} else {
			p.AddAddon(mapRemote)
		}
	}

	if config.MapLocal != "" {
		mapLocal, err := addon.NewMapLocalFromFile(config.MapLocal)
		if err != nil {
			log.Warnf("load map local error: %v", err)
		} else {
			p.AddAddon(mapLocal)
		}
	}

	if config.Dump != "" {
		dumper := addon.NewDumperWithFilename(config.Dump, config.DumpLevel)
		p.AddAddon(dumper)
	}

	log.Fatal(p.Start())
}

func matchHost(address string, hosts []string) bool {
	hostname, port := splitHostPort(address)
	for _, host := range hosts {
		h, p := splitHostPort(host)
		if matchHostname(hostname, h) && (p == "" || p == port) {
			return true
		}
	}
	return false
}

func matchHostname(hostname string, h string) bool {
	if h == "*" {
		return true
	}
	if strings.HasPrefix(h, "*.") {
		return hostname == h[2:] || strings.HasSuffix(hostname, h[1:])
	}
	return h == hostname
}

func splitHostPort(address string) (string, string) {
	index := strings.LastIndex(address, ":")
	if index == -1 {
		return address, ""
	}
	return address[:index], address[index+1:]
}

func WriteRecord(recordDir string, records chan string) {
	currentTime := time.Now()
	fileName := currentTime.Format("20060102150405") + ".log"

	fileLock := sync.Mutex{}

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()

	for {
		select {
		case data, ok := <-records:
			if !ok {
				fileLock.Lock()
				file.Close()
				fileLock.Unlock()
				return
			}
			_, err := file.WriteString(data + "\n")
			if err != nil {
				fmt.Println("Error writing to file:", err)
				panic(err)
			}
		case <-timer.C:
			fileLock.Lock()
			file.Close()

			// 移动文件到目录B
			newPath := filepath.Join(recordDir, filepath.Base(fileName))
			err := os.Rename(fileName, newPath)
			if err != nil {
				fmt.Println("Error moving file:", err)
				panic(err)
			}

			currentTime = time.Now()
			fileName = currentTime.Format("20060102150405") + ".log"
			file, err = os.Create(fileName)
			if err != nil {
				fmt.Println("Error creating file:", err)
				panic(err)
			}
			fmt.Println("Switched to new file:", fileName)
			timer.Reset(60 * time.Second)
			fileLock.Unlock()
		}
	}
}
