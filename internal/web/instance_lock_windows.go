//go:build windows

package web

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openInstanceFile(path string) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			return nil, fmt.Errorf("inspect instance lock: %w; close instance lock: %v", err, closeErr)
		}
		return nil, fmt.Errorf("inspect instance lock: %w", err)
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || information.NumberOfLinks != 1 {
		if err := windows.CloseHandle(handle); err != nil {
			return nil, fmt.Errorf("instance lock is not a private regular file; close instance lock: %v", err)
		}
		return nil, fmt.Errorf("instance lock is not a private regular file")
	}
	return os.NewFile(uintptr(handle), path), nil
}

func validateStateFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state file to inspect identity: %w", err)
	}
	var information windows.ByHandleFileInformation
	inspectErr := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information)
	closeErr := file.Close()
	if inspectErr != nil && closeErr != nil {
		return fmt.Errorf("inspect state file identity: %w; close state file: %v", inspectErr, closeErr)
	}
	if inspectErr != nil {
		return fmt.Errorf("inspect state file identity: %w", inspectErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close state file after inspecting identity: %w", closeErr)
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fmt.Errorf("state file is not a regular file")
	}
	if information.NumberOfLinks != 1 {
		return fmt.Errorf("state file must not have multiple hard links")
	}
	return nil
}

func tryLockInstanceFile(file *os.File) (func() error, bool, error) {
	// Lock outside the metadata range because Windows byte-range locks are
	// mandatory and a waiting process must still read the file.
	overlapped := &windows.Overlapped{Offset: ^uint32(0), OffsetHigh: 0x7fffffff}
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return func() error {
		return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
	}, true, nil
}
