//go:build !windows

package monitor

import "syscall"

func diskSnapshot(path string) (DiskSnapshot, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskSnapshot{Path: path}, err
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	var usage float64
	if total > 0 {
		usage = round1(float64(used) * 100 / float64(total))
	}

	return DiskSnapshot{
		Path:         path,
		TotalBytes:   total,
		UsedBytes:    used,
		FreeBytes:    free,
		UsagePercent: usage,
	}, nil
}
