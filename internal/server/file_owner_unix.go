//go:build !windows

package server

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func fileOwner(_ string, info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return "unknown"
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	owner, err := user.LookupId(uid)
	if err == nil && owner != nil {
		if owner.Username != "" {
			return owner.Username
		}
		if owner.Name != "" {
			return owner.Name
		}
	}
	return uid
}
