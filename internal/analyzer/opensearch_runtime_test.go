package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOpenSearchRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		openSearchRuntimeTestResource("red", "red", "3", "0", "0", "20"),
		openSearchRuntimeTestResource("yellow", "yellow", "2", "0", "0", "20"),
		openSearchRuntimeTestResource("pending", "green", "0", "12", "6000", "20"),
		openSearchRuntimeTestResource("dense", "green", "0", "0", "0", "120.5"),
		openSearchRuntimeTestResource("no-data", "green", "0", "0", "0", "0"),
		openSearchRuntimeTestResource("incomplete", "green", "0", "0", "0", "20"),
		openSearchRuntimeTestResource("disk", "green", "0", "0", "0", "20"),
		openSearchRuntimeTestResource("heap", "green", "0", "0", "0", "20"),
		openSearchRuntimeTestResource("fd", "green", "0", "0", "0", "20"),
		openSearchRuntimeTestResource("healthy", "green", "0", "0", "0", "20"),
	}
	resources[4].Metadata[model.MetadataOpenSearchDataNodeCount] = "0"
	resources[5].Metadata[model.MetadataOpenSearchNodeStatsTotal] = "3"
	resources[5].Metadata[model.MetadataOpenSearchNodeStatsSuccessful] = "2"
	resources[5].Metadata[model.MetadataOpenSearchNodeStatsFailed] = "1"
	resources[6].Metadata[model.MetadataOpenSearchMaxDiskUsedPercent] = "90"
	resources[7].Metadata[model.MetadataOpenSearchMaxHeapUsedPercent] = "90"
	resources[8].Metadata[model.MetadataOpenSearchMaxFDUsedPercent] = "90"
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{
		"opensearch_pending_task_threshold":          10,
		"opensearch_task_wait_threshold":             5 * time.Second,
		"opensearch_shards_per_data_node_threshold":  100,
		"opensearch_disk_usage_threshold":            85,
		"opensearch_disk_usage_critical_threshold":   95,
		"opensearch_heap_usage_threshold":            85,
		"opensearch_file_descriptor_usage_threshold": 80,
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		typ      string
		severity model.Severity
		category model.FindingCategory
	}{
		{NewOpenSearchClusterRedAnalyzer(), "red", "OpenSearchClusterRed", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOpenSearchClusterYellowAnalyzer(), "yellow", "OpenSearchClusterYellow", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOpenSearchPendingTasksAnalyzer(), "pending", "OpenSearchPendingTasks", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOpenSearchHighShardDensityAnalyzer(), "dense", "OpenSearchHighShardDensity", model.SeverityWarning, model.FindingCategoryCost},
		{NewOpenSearchNoDataNodesAnalyzer(), "no-data", "OpenSearchNoDataNodes", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOpenSearchNodeStatsIncompleteAnalyzer(), "incomplete", "OpenSearchNodeStatsIncomplete", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOpenSearchHighDiskUsageAnalyzer(), "disk", "OpenSearchHighDiskUsage", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOpenSearchHighHeapUsageAnalyzer(), "heap", "OpenSearchHighHeapUsage", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOpenSearchHighFDUsageAnalyzer(), "fd", "OpenSearchHighFileDescriptorUsage", model.SeverityWarning, model.FindingCategoryReliability},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources, Config: config})
		if err != nil {
			t.Fatalf("%s execute: %v", test.analyzer.ID(), err)
		}
		if len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Type != test.typ ||
			findings[0].Severity != test.severity || findings[0].Category != test.category {
			t.Fatalf("%s unexpected findings %#v", test.analyzer.ID(), findings)
		}
		if model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
			t.Fatalf("%s default category mismatch", test.analyzer.ID())
		}
	}
}

func openSearchRuntimeTestResource(id, status, unassigned, pending, waitMillis, density string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "OpenSearch Cluster",
		Source: model.SourceInfo{System: "opensearch", Instance: "https://" + id},
		Metadata: map[string]string{
			model.MetadataOpenSearchHealthAvailable:     "true",
			model.MetadataOpenSearchClusterStatus:       status,
			model.MetadataOpenSearchUnassignedShards:    unassigned,
			model.MetadataOpenSearchPendingTasks:        pending,
			model.MetadataOpenSearchMaxTaskWaitMillis:   waitMillis,
			model.MetadataOpenSearchShardsPerDataNode:   density,
			model.MetadataOpenSearchDataNodeCount:       "1",
			model.MetadataOpenSearchNodeStatsAvailable:  "true",
			model.MetadataOpenSearchNodeStatsTotal:      "1",
			model.MetadataOpenSearchNodeStatsSuccessful: "1",
			model.MetadataOpenSearchNodeStatsFailed:     "0",
			model.MetadataOpenSearchDiskStatsNodeCount:  "1",
			model.MetadataOpenSearchMaxDiskUsedPercent:  "10",
			model.MetadataOpenSearchHeapStatsNodeCount:  "1",
			model.MetadataOpenSearchMaxHeapUsedPercent:  "10",
			model.MetadataOpenSearchFDStatsNodeCount:    "1",
			model.MetadataOpenSearchMaxFDUsedPercent:    "10",
		},
		Status: model.ResourceStatusActive,
	}
}

func TestOpenSearchHighDiskUsageBecomesCriticalAtCriticalThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := openSearchRuntimeTestResource("disk-critical", "green", "0", "0", "0", "20")
	resource.Metadata[model.MetadataOpenSearchMaxDiskUsedPercent] = "96"
	resource.Metadata[model.MetadataOpenSearchMinDiskAvailable] = "1024"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}
	findings, err := NewOpenSearchHighDiskUsageAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"opensearch_disk_usage_threshold":          85,
			"opensearch_disk_usage_critical_threshold": 95,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected one critical disk finding, got %#v", findings)
	}
}

func TestElasticsearchRuntimeAnalyzersUseIndependentIdentityAndThresholds(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := openSearchRuntimeTestResource("elastic-red", "red", "2", "0", "0", "20")
	resource.Name = "Elasticsearch Cluster"
	resource.Source.System = "elasticsearch"
	elasticsearchMetadata := make(map[string]string, len(resource.Metadata))
	for key, value := range resource.Metadata {
		elasticsearchMetadata[strings.Replace(key, "opensearch_", "elasticsearch_", 1)] = value
	}
	resource.Metadata = elasticsearchMetadata
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatal(err)
	}

	findings, err := NewElasticsearchClusterRedAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"elasticsearch_disk_usage_threshold": 99},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Type != "ElasticsearchClusterRed" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Resource.ID != resource.ID {
		t.Fatalf("unexpected Elasticsearch findings %#v", findings)
	}
	if findings, err := NewOpenSearchClusterRedAnalyzer().Execute(ctx, Context{Resources: store.Resources}); err != nil || len(findings) != 0 {
		t.Fatalf("OpenSearch analyzer must not consume Elasticsearch resources: %#v err=%v", findings, err)
	}

	constructors := []Analyzer{
		NewElasticsearchClusterYellowAnalyzer(),
		NewElasticsearchPendingTasksAnalyzer(),
		NewElasticsearchHighShardDensityAnalyzer(),
		NewElasticsearchNoDataNodesAnalyzer(),
		NewElasticsearchNodeStatsIncompleteAnalyzer(),
		NewElasticsearchHighDiskUsageAnalyzer(),
		NewElasticsearchHighHeapUsageAnalyzer(),
		NewElasticsearchHighFDUsageAnalyzer(),
	}
	for _, analyzer := range constructors {
		if analyzer.ID() == "" || analyzer.Name() == "" || analyzer.InputTypes()[0] != model.ResourceTypeInstance {
			t.Fatalf("invalid Elasticsearch analyzer contract %#v", analyzer)
		}
	}
}
