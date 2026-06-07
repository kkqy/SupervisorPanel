//go:build windows

package monitor

import "fmt"

func diskSnapshot(path string) (DiskSnapshot, error) {
	return DiskSnapshot{Path: path}, fmt.Errorf("磁盘监控暂不支持 Windows")
}
