//go:build windows

package server

import (
	"os"
	"os/user"
)

func fileOwner(_ string, _ os.FileInfo) string {
	current, err := user.Current()
	if err == nil && current != nil {
		if current.Username != "" {
			return current.Username
		}
		if current.Name != "" {
			return current.Name
		}
	}
	return "unknown"
}
