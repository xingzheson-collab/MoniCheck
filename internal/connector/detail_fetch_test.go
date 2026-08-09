package connector

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedDetailFetchLimitsConcurrencyAndPreservesOrder(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32

	results, workerCount := boundedDetailFetch(context.Background(), 6, 2, func(_ context.Context, index int) (string, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		defer active.Add(-1)
		time.Sleep(time.Duration(6-index) * 5 * time.Millisecond)
		return fmt.Sprintf("item-%d", index), nil
	})

	if workerCount != 2 {
		t.Fatalf("expected two workers, got %d", workerCount)
	}
	if maximum.Load() > 2 {
		t.Fatalf("expected at most two concurrent fetches, got %d", maximum.Load())
	}
	for index, result := range results {
		expected := fmt.Sprintf("item-%d", index)
		if result.Err != nil || result.Value != expected {
			t.Fatalf("result %d lost input order: %#v", index, result)
		}
	}
}

func TestBoundedDetailFetchNormalizesWorkerCount(t *testing.T) {
	_, workerCount := boundedDetailFetch(context.Background(), maxConnectorDetailWorkers+1, maxConnectorDetailWorkers+20, func(_ context.Context, index int) (int, error) {
		return index, nil
	})
	if workerCount != maxConnectorDetailWorkers {
		t.Fatalf("expected worker cap %d, got %d", maxConnectorDetailWorkers, workerCount)
	}

	results, workerCount := boundedDetailFetch(context.Background(), 0, 0, func(_ context.Context, index int) (int, error) {
		return index, nil
	})
	if workerCount != 0 || len(results) != 0 {
		t.Fatalf("expected an empty fetch, got workers=%d results=%#v", workerCount, results)
	}
}

func TestUniqueNonEmptyStringsPreservesFirstSeenOrder(t *testing.T) {
	values := uniqueNonEmptyStrings([]string{" checkout ", "", "payments", "checkout", " payments ", "search"})
	expected := []string{"checkout", "payments", "search"}
	if len(values) != len(expected) {
		t.Fatalf("expected %#v, got %#v", expected, values)
	}
	for index := range expected {
		if values[index] != expected[index] {
			t.Fatalf("expected %#v, got %#v", expected, values)
		}
	}
}
