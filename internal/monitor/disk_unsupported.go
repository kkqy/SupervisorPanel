//go:build !linux

package monitor

import "fmt"

func diskSnapshot(path string) (DiskSnapshot, error) {
	return DiskSnapshot{Path: path}, fmt.Errorf("磁盘监控仅支持 Linux")
}
