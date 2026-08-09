package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelScraperErrorsAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	errored := otelcolScraperRuntimeResource("errored", "true", "17")
	healthy := otelcolScraperRuntimeResource("healthy", "true", "0")
	unavailable := otelcolScraperRuntimeResource("unavailable", "false", "17")
	wrongSource := otelcolScraperRuntimeResource("wrong-source", "true", "17")
	wrongSource.Source.System = "plugin"
	inactive := otelcolScraperRuntimeResource("inactive", "true", "17")
	inactive.Status = model.ResourceStatusOrphan
	for _, resource := range []model.Resource{errored, healthy, unavailable, wrongSource, inactive} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	item := NewOTelScraperErrorsAnalyzer()
	findings, err := item.Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != errored.ID ||
		findings[0].Type != "OTelScraperErrors" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		!strings.Contains(findings[0].Evidence[0], "17 metric point collection error(s)") ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	encoded, err := json.Marshal(findings[0])
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	for _, privateValue := range []string{"private-scraper", "private-receiver", "private-instance", "private-label"} {
		if strings.Contains(string(encoded), privateValue) {
			t.Fatalf("finding leaked %q: %s", privateValue, encoded)
		}
	}
}

func TestOTelScraperErrorsAnalyzerPrefersCounterDelta(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	stable := otelcolScraperRuntimeResource("stable-delta", "true", "17")
	growing := otelcolScraperRuntimeResource("growing-delta", "true", "18")
	for _, resource := range []*model.Resource{&stable, &growing} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
	}
	stable.Metadata[model.MetadataOTelScraperErrorDelta] = "0"
	growing.Metadata[model.MetadataOTelScraperErrorDelta] = "1"
	for _, resource := range []model.Resource{stable, growing} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewOTelScraperErrorsAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != growing.ID ||
		findings[0].Metadata["counter_evidence"] != "delta" ||
		findings[0].Metadata["counter_delta"] != "1" {
		t.Fatalf("unexpected scraper delta finding: findings=%#v err=%v", findings, err)
	}
}

func TestOTelScraperErrorRatioAnalyzersAreMutuallyExclusive(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	low := otelcolScraperRuntimeResource("low-ratio", "true", "20")
	high := otelcolScraperRuntimeResource("high-ratio", "true", "20")
	for _, resource := range []*model.Resource{&low, &high} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
		resource.Metadata[model.MetadataOTelScraperErrorDelta] = "10"
		resource.Metadata[model.MetadataOTelScraperScrapedMetricsAvailable] = "true"
		resource.Metadata[model.MetadataOTelScraperScrapedMetricPointsDelta] = "90"
		resource.Metadata[model.MetadataOTelScraperErrorRatioEvaluable] = "true"
	}
	low.Metadata[model.MetadataOTelScraperErrorRatioPercent] = "9.99"
	high.Metadata[model.MetadataOTelScraperErrorRatioPercent] = "10"
	for _, resource := range []model.Resource{low, high} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	ordinary, err := NewOTelScraperErrorsAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(ordinary) != 1 || ordinary[0].Resource.ID != low.ID {
		t.Fatalf("unexpected ordinary scraper findings: %#v err=%v", ordinary, err)
	}
	critical, err := NewOTelScraperHighErrorRatioAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(critical) != 1 ||
		critical[0].Resource.ID != high.ID ||
		critical[0].Type != "OTelScraperHighErrorRatio" ||
		critical[0].Severity != model.SeverityCritical ||
		critical[0].Category != model.FindingCategoryReliability ||
		critical[0].Metadata["errored_delta"] != "10" ||
		critical[0].Metadata["scraped_delta"] != "90" ||
		critical[0].Metadata["error_ratio_percent"] != "10" {
		t.Fatalf("unexpected high scraper-ratio findings: %#v err=%v", critical, err)
	}
}

func otelcolScraperRuntimeResource(id, available, errors string) model.Resource {
	return model.Resource{
		ID:     "otelcol-scraper-runtime-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:    available,
			model.MetadataOTelScraperErroredMetricPoints: errors,
		},
	}
}
