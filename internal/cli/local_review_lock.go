package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const localReviewLockFileName = "review.lock"

type localReviewLock struct {
	path string
	file *os.File
}

func acquireLocalReviewLock(store localReviewStore) (*localReviewLock, error) {
	lockDir := filepath.Dir(store.runsDir)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare local review lock directory: %w", err)
	}

	lockPath := filepath.Join(lockDir, localReviewLockFileName)

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open local review lock: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)

	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			_ = file.Truncate(0)
			_, _ = file.Seek(0, 0)
			_, _ = fmt.Fprintf(file, "pid=%d\ncreated_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			return &localReviewLock{
				path: lockPath,
				file: file,
			}, nil
		}

		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire local review lock: %w", err)
		}

		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("local review store is busy: another rygnal process is writing audit artifacts; retry in a few seconds")
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func (lock *localReviewLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}

	var releaseErr error

	if err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN); err != nil {
		releaseErr = fmt.Errorf("unlock local review lock %s: %w", lock.path, err)
	}

	if err := lock.file.Close(); err != nil {
		if releaseErr != nil {
			return fmt.Errorf("%v; close local review lock: %w", releaseErr, err)
		}
		return fmt.Errorf("close local review lock: %w", err)
	}

	return releaseErr
}

func withLocalReviewLock(store localReviewStore, action func() error) error {
	lock, err := acquireLocalReviewLock(store)
	if err != nil {
		return err
	}

	defer func() {
		_ = lock.Release()
	}()

	return action()
}
