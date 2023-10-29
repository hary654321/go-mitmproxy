package main

import "C"
import (
	"errors"
	"fmt"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	rawLog "log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Trisia/gosysproxy"
	"github.com/lqqyt2423/go-mitmproxy/addon"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/web"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	version bool // show go-mitmproxy version

	Addr        string   // proxy listen addr
	WebAddr     string   // web interface listen addr
	SslInsecure bool     // not verify upstream server SSL/TLS certificates.
	IgnoreHosts []string // a list of ignore hosts
	AllowHosts  []string // a list of allow hosts
	CertPath    string   // path of generate cert files
	Debug       int      // debug mode: 1 - print debug log, 2 - show debug from
	Dump        string   // dump filename
	DumpLevel   int      // dump level: 0 - header, 1 - header + body
	Upstream    string   // upstream proxy
	MapRemote   string   // map remote config filename
	MapLocal    string   // map local config filename

	filename string // read config from the filename

	RecordDir string // 访问记录保存目录
}

//export Start
func Start() {
	config := loadConfig()
	recordDir, err := checkRecordDir(config.RecordDir)
	if err != nil {
		log.Fatal(err)
	}
	config.RecordDir = recordDir

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

	if config.version {
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

	go WriteRecord(config.RecordDir, recordChan)
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

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-stopChan:
				fmt.Println("Received signal. Cleaning up...")
				// 执行清理操作
				// 例如：关闭数据库连接、保存文件等
				time.Sleep(2 * time.Second) // 模拟清理操作
				fmt.Println("Cleanup completed. Exiting.")
				os.Exit(0)
			default:
				// 执行您的长时间运行的操作
				fmt.Println("Performing operation...")
				time.Sleep(time.Second)
			}
		}
	}()
	log.Fatal(p.Start())
	p.Shutdown()
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

func checkRecordDir(dirPath string) (string, error) {
	if dirPath == "" {
		// 要检查的文件夹名称
		folderName := "records"
		// 获取当前目录
		currentDir, err := os.Getwd()
		if err != nil {
			return "", err
		}

		// 拼接文件夹的完整路径
		folderPath := filepath.Join(currentDir, folderName)

		// 检查文件夹是否存在
		_, err = os.Stat(folderPath)
		if os.IsNotExist(err) {
			// 文件夹不存在，创建它
			err = os.Mkdir(folderPath, 0755)
			if err != nil {
				return "", err
			}
			fmt.Println("文件夹创建成功:", folderPath)
		} else if err != nil {
			// 其他错误，无法判断文件夹是否存在
			fmt.Println("无法判断文件夹是否存在:", err)
			return "", err
		} else {
			// 文件夹已存在
			fmt.Println("文件夹已存在:", folderPath)
		}
		return folderPath, nil
	} else {
		// 检查目录是否存在
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			return "", err
		}

		// 获取目录的文件信息
		dirInfo, err := os.Stat(dirPath)
		if err != nil {
			return "", err
		}

		// 检查是否为目录
		if !dirInfo.IsDir() {
			return "", errors.New("error dir")
		}

		// 获取当前日期，并格式化为年月日的字符串
		date := time.Now().Format("20060102")
		logFileName := date + ".log"

		// 打开日志文件，如果不存在则创建，存在则追加写入
		logFile, err := os.OpenFile(path.Join(dirPath, logFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return "", err
		}
		defer logFile.Close()
		return dirPath, err
	}
}

func WriteRecord(currentDir, recordDir string, records chan string) {

	currentTime := time.Now()
	fileName := currentTime.Format("20060102150405") + ".log"

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
		case data := <-records:
			_, err := file.WriteString(data)
			if err != nil {
				fmt.Println("Error writing to file:", err)
				panic(err)
			}
		case <-timer.C:
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
		}
	}
	//
	//var currentFile *os.File
	//var currentDate string
	//
	//for record := range records {
	//	// 获取当前日期，并格式化为年月日的字符串
	//	date := time.Now().Format("20060102")
	//
	//	// 判断是否需要创建新的文件
	//	if currentDate != date || currentFile == nil {
	//		// 关闭旧文件（如果有的话）
	//		if currentFile != nil {
	//			currentFile.Close()
	//		}
	//
	//		// 设置新的日期和文件名
	//		currentDate = date
	//		fileName := currentDate + ".log"
	//
	//		// 拼接文件的完整路径
	//		filePath := filepath.Join(recordDir, fileName)
	//
	//		// 创建或打开文件（使用追加写入方式）
	//		var err error
	//		currentFile, err = os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	//		if err != nil {
	//			fmt.Println("打开文件失败:", err)
	//			return
	//		}
	//	}
	//
	//	// 将数据写入文件
	//	_, err := currentFile.WriteString(record + "\n")
	//	if err != nil {
	//		fmt.Println("写入文件失败:", err)
	//		return
	//	}
	//}
	//
	//// 关闭最后一个文件（如果有的话）
	//if currentFile != nil {
	//	currentFile.Close()
	//}

}

func main() {

}
