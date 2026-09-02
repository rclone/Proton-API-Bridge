package proton_api_bridge

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

func TestCollectUploadErrorsReleasesAllWorkersAfterFailure(t *testing.T) {
	const (
		batchSize = int64(8)
		slotCount = int64(20)
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	slots := semaphore.NewWeighted(slotCount)

	for batch := 0; batch < 4; batch++ {
		results := make(chan error)
		for block := int64(0); block < batchSize; block++ {
			go func(fail bool) {
				if err := slots.Acquire(ctx, 1); err != nil {
					results <- err
					return
				}
				defer slots.Release(1)
				if fail {
					results <- errors.New("synthetic upload failure")
					return
				}
				results <- nil
			}(block == 0)
		}

		if err := collectUploadErrors(results, int(batchSize)); err == nil {
			t.Fatal("expected the first upload failure to be returned")
		}
	}

	if err := slots.Acquire(ctx, slotCount); err != nil {
		t.Fatalf("upload workers leaked semaphore slots: %v", err)
	}
	slots.Release(slotCount)
}
