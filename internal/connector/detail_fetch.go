package connector

import (
	"context"
	"strings"
	"sync"
)

const (
	defaultConnectorDetailWorkers = 8
	maxConnectorDetailWorkers     = 64
)

type detailFetchResult[T any] struct {
	Value T
	Err   error
}

func boundedDetailFetch[T any](
	ctx context.Context,
	itemCount int,
	requestedWorkers int,
	fetch func(context.Context, int) (T, error),
) ([]detailFetchResult[T], int) {
	if itemCount <= 0 {
		return []detailFetchResult[T]{}, 0
	}

	workerCount := requestedWorkers
	if workerCount <= 0 {
		workerCount = defaultConnectorDetailWorkers
	}
	if workerCount > maxConnectorDetailWorkers {
		workerCount = maxConnectorDetailWorkers
	}
	if workerCount > itemCount {
		workerCount = itemCount
	}

	results := make([]detailFetchResult[T], itemCount)
	jobs := make(chan int, itemCount)
	for index := 0; index < itemCount; index++ {
		jobs <- index
	}
	close(jobs)

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index].Value, results[index].Err = fetch(ctx, index)
			}
		}()
	}
	workers.Wait()
	return results, workerCount
}

func uniqueNonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
