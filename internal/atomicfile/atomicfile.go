package atomicfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func WriteJSON(path string, v any) (resultErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	file, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary file %q: %w", tmp, err))
			}
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return errors.Join(err, closeFile(file))
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return errors.Join(err, closeFile(file))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, closeFile(file))
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return syncDir(dir)
}

func closeFile(file *os.File) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %q: %w", file.Name(), err)
	}
	return nil
}
