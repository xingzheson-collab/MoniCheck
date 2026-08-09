package report

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

type TSDBCostSummary struct {
	TSDBCount        int                `json:"tsdb_count"`
	HeadSeries       int64              `json:"tsdb_head_series"`
	HeadChunks       int64              `json:"tsdb_head_chunks"`
	LabelValueCount  int64              `json:"tsdb_label_value_count"`
	LabelMemoryBytes int64              `json:"tsdb_label_memory_bytes"`
	Instances        []TSDBCostInstance `json:"tsdb_instances"`
}

type TSDBCostInstance struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	System           string `json:"system"`
	Instance         string `json:"instance"`
	HeadSeries       int64  `json:"head_series"`
	HeadChunks       int64  `json:"head_chunks"`
	HeadRangeSeconds int64  `json:"head_range_seconds"`
	LabelValueCount  int64  `json:"label_value_count"`
	LabelMemoryBytes int64  `json:"label_memory_bytes"`
}

func BuildTSDBCostSummary(ctx context.Context, store *storage.Store, filter storage.ResourceFilter) (TSDBCostSummary, error) {
	filter.Type = model.ResourceTypeTSDB
	resources, err := store.Resources.List(ctx, filter)
	if err != nil {
		return TSDBCostSummary{}, err
	}
	summary := TSDBCostSummary{Instances: make([]TSDBCostInstance, 0, len(resources))}
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		item := TSDBCostInstance{
			ID:               resource.ID,
			Name:             resource.Name,
			System:           resource.Source.System,
			Instance:         resource.Source.Instance,
			HeadSeries:       reportMetadataInt64(resource, model.MetadataTSDBHeadSeries),
			HeadChunks:       reportMetadataInt64(resource, model.MetadataTSDBHeadChunks),
			HeadRangeSeconds: reportMetadataInt64(resource, model.MetadataTSDBHeadRangeSeconds),
			LabelValueCount:  reportMetadataInt64(resource, model.MetadataTSDBLabelValueCount),
			LabelMemoryBytes: reportMetadataInt64(resource, model.MetadataTSDBLabelMemoryBytes),
		}
		summary.TSDBCount++
		summary.HeadSeries += item.HeadSeries
		summary.HeadChunks += item.HeadChunks
		summary.LabelValueCount += item.LabelValueCount
		summary.LabelMemoryBytes += item.LabelMemoryBytes
		summary.Instances = append(summary.Instances, item)
	}
	sort.Slice(summary.Instances, func(i, j int) bool {
		if summary.Instances[i].System == summary.Instances[j].System {
			return summary.Instances[i].Instance < summary.Instances[j].Instance
		}
		return summary.Instances[i].System < summary.Instances[j].System
	})
	return summary, nil
}

func reportMetadataInt64(resource model.Resource, key string) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(resource.Metadata[key]), 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}
