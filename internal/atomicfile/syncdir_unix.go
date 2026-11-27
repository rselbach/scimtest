//go:build !windows

package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EROFS) {
			return file.Close()
		}
		closeErr := file.Close()
		if closeErr != nil {
			return fmt.Errorf("sync directory %q: %w; close directory: %v", dir, err, closeErr)
		}
		return fmt.Errorf("sync directory %q: %w", dir, err)
	}
	return file.Close()
}
