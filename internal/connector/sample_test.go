package connector

import (
	"context"
	"testing"

	"monicheck/internal/model"
)

func TestSampleConnectorIncludesCostOpportunityMeasurements(t *testing.T) {
	snapshot, err := NewSampleConnector().Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"http_requests_total":       "12500",
		"node_cpu_seconds_total":    "24000",
		"legacy_worker_queue_depth": "3500",
	}
	for _, resource := range snapshot.Resources {
		count, ok := expected[resource.Name]
		if !ok {
			continue
		}
		if resource.Metadata[model.MetadataSeriesCount] != count ||
			resource.Metadata[model.MetadataSeriesCountSource] != "tsdb_head" {
			t.Fatalf("unexpected sample cost measurement for %s: %#v", resource.Name, resource.Metadata)
		}
		delete(expected, resource.Name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing sample cost measurements: %#v", expected)
	}
}
