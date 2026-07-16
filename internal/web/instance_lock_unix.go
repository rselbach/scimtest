//go:build darwin || linux

package web

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openInstanceFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("inspect instance lock: %w; close instance lock: %v", err, closeErr)
		}
		return nil, fmt.Errorf("inspect instance lock: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("instance lock is not a private regular file owned by the current user; close instance lock: %v", err)
		}
		return nil, fmt.Errorf("instance lock is not a private regular file owned by the current user")
	}
	return file, nil
}

func validateStateFile(path string) error {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return fmt.Errorf("inspect state file identity: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("state file is not a regular file")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("state file must not have multiple hard links")
	}
	return nil
}

func tryLockInstanceFile(file *os.File) (func() error, bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() error {
		return unix.Flock(int(file.Fd()), unix.LOCK_UN)
	}, true, nil
}
