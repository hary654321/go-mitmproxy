package cert

import (
	"bytes"
	"os/exec"
	"strings"
)

func InstallCert(certPath string) (bool, error) {
	// 构建 certutil.exe 的执行命令
	cmd := exec.Command("certutil", "-addstore", "Root", certPath)
	// 设置标准输出和标准错误输出缓冲区
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		return false, err
	}

	if !strings.Contains(stdout.String(), "mitmproxy") {
		return false, nil
	}

	return true, nil
}
