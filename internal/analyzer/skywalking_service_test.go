package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSkyWalkingServiceWithoutInstanceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		skyWalkingTestService("checkout", "true", "true", "0", ""),
		skyWalkingTestService("payments", "true", "true", "2", ""),
		skyWalkingTestService("mysql", "true", "false", "0", ""),
		skyWalkingTestService("unknown", "false", "true", "0", ""),
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewSkyWalkingServiceWithoutInstanceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.Name != "checkout" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("expected checkout reliability finding, got %#v", findings)
	}
}

func TestSkyWalkingEndpointDiscoveryTruncatedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	truncated := skyWalkingTestService("checkout", "true", "true", "1", "true")
	truncated.Metadata[model.MetadataAPMEndpointCount] = "1000"
	truncated.Metadata[model.MetadataAPMEndpointLimit] = "1000"
	complete := skyWalkingTestService("payments", "true", "true", "1", "")
	for _, resource := range []model.Resource{truncated, complete} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewSkyWalkingEndpointDiscoveryTruncatedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.Name != "checkout" ||
		findings[0].Metadata["endpoint_limit"] != "1000" {
		t.Fatalf("expected endpoint truncation finding, got %#v", findings)
	}
}

func TestSkyWalkingServiceAlarmBurstAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	burst := skyWalkingTestService("checkout", "true", "true", "1", "")
	burst.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] = "true"
	burst.Metadata[model.MetadataAPMAlarmCount] = "9"
	burst.Metadata[model.MetadataAPMActiveAlarmCount] = "7"
	burst.Metadata[model.MetadataAPMRecoveredAlarmCount] = "2"
	burst.Metadata[model.MetadataAPMAlarmDiscoveryTruncated] = "true"
	quiet := skyWalkingTestService("payments", "true", "true", "1", "")
	quiet.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] = "true"
	quiet.Metadata[model.MetadataAPMActiveAlarmCount] = "2"
	unavailable := skyWalkingTestService("inventory", "true", "true", "1", "")
	unavailable.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] = "false"
	unavailable.Metadata[model.MetadataAPMActiveAlarmCount] = "20"
	for _, resource := range []model.Resource{burst, quiet, unavailable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewSkyWalkingServiceAlarmBurstAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"skywalking_active_alarm_threshold": 5},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.Name != "checkout" ||
		findings[0].Metadata["active_alarm_count"] != "7" ||
		findings[0].Metadata["count_truncated"] != "true" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("expected truncated checkout alarm burst finding, got %#v", findings)
	}
}

func skyWalkingTestService(name string, catalog string, normal string, instanceCount string, truncated string) model.Resource {
	return model.Resource{
		ID:     "skywalking-" + name,
		Type:   model.ResourceTypeService,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "skywalking"},
		Metadata: map[string]string{
			model.MetadataAPMCatalogService:             catalog,
			model.MetadataAPMNormal:                     normal,
			model.MetadataAPMInstanceDiscoveryAvailable: "true",
			model.MetadataAPMInstanceCount:              instanceCount,
			model.MetadataAPMLookback:                   "1h0m0s",
			model.MetadataAPMEndpointDiscoveryTruncated: truncated,
		},
	}
}
