package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		prometheusRuntimeTestResource("reload-failed", "false", "0"),
		prometheusRuntimeTestResource("corrupt", "true", "2"),
		prometheusRuntimeTestResource("healthy", "true", "0"),
	}
	unavailable := prometheusRuntimeTestResource("unavailable", "false", "2")
	unavailable.Metadata[model.MetadataPrometheusRuntimeAvailable] = "false"
	missing := prometheusRuntimeTestResource("missing-fields", "", "")
	delete(missing.Metadata, model.MetadataPrometheusReloadSuccess)
	delete(missing.Metadata, model.MetadataPrometheusCorruptionCount)
	deprecated := prometheusRuntimeTestResource("deprecated", "false", "2")
	deprecated.Status = model.ResourceStatusDeprecated
	adminEnabled := prometheusRuntimeTestResource("admin-enabled", "true", "0")
	adminEnabled.Metadata[model.MetadataPrometheusFlagsAvailable] = "true"
	adminEnabled.Metadata[model.MetadataPrometheusAdminAPIEnabled] = "true"
	lifecycleEnabled := prometheusRuntimeTestResource("lifecycle-enabled", "true", "0")
	lifecycleEnabled.Metadata[model.MetadataPrometheusFlagsAvailable] = "true"
	lifecycleEnabled.Metadata[model.MetadataPrometheusLifecycleAPIEnabled] = "true"
	remoteWriteEnabled := prometheusRuntimeTestResource("remote-write-enabled", "true", "0")
	remoteWriteEnabled.Metadata[model.MetadataPrometheusFlagsAvailable] = "true"
	remoteWriteEnabled.Metadata[model.MetadataPrometheusRemoteWriteReceiver] = "true"
	otlpEnabled := prometheusRuntimeTestResource("otlp-enabled", "true", "0")
	otlpEnabled.Metadata[model.MetadataPrometheusFlagsAvailable] = "true"
	otlpEnabled.Metadata[model.MetadataPrometheusOTLPReceiver] = "true"
	flagsUnavailable := prometheusRuntimeTestResource("flags-unavailable", "true", "0")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusAdminAPIEnabled] = "true"
	flagsUnavailable.Metadata[model.MetadataPrometheusLifecycleAPIEnabled] = "true"
	flagsUnavailable.Metadata[model.MetadataPrometheusRemoteWriteReceiver] = "true"
	flagsUnavailable.Metadata[model.MetadataPrometheusOTLPReceiver] = "true"
	resources = append(resources, unavailable, missing, deprecated, adminEnabled, lifecycleEnabled, remoteWriteEnabled, otlpEnabled, flagsUnavailable)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	reload, err := NewPrometheusConfigReloadFailedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute reload analyzer: %v", err)
	}
	if len(reload) != 1 ||
		reload[0].Resource.ID != "reload-failed" ||
		reload[0].Type != "PrometheusConfigReloadFailed" ||
		reload[0].Severity != model.SeverityCritical ||
		reload[0].Category != model.FindingCategoryConfiguration ||
		model.DefaultFindingCategory(reload[0].Type, reload[0].Resource.Type) != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected reload findings: %#v", reload)
	}

	corruption, err := NewPrometheusTSDBCorruptionDetectedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute corruption analyzer: %v", err)
	}
	if len(corruption) != 1 ||
		corruption[0].Resource.ID != "corrupt" ||
		corruption[0].Type != "PrometheusTSDBCorruptionDetected" ||
		corruption[0].Severity != model.SeverityCritical ||
		corruption[0].Category != model.FindingCategoryReliability ||
		corruption[0].Metadata["corruption_count"] != "2" ||
		model.DefaultFindingCategory(corruption[0].Type, corruption[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected corruption findings: %#v", corruption)
	}

	admin, err := NewPrometheusAdminAPIEnabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute admin API analyzer: %v", err)
	}
	if len(admin) != 1 ||
		admin[0].Resource.ID != "admin-enabled" ||
		admin[0].Type != "PrometheusAdminAPIEnabled" ||
		admin[0].Severity != model.SeverityCritical ||
		admin[0].Category != model.FindingCategorySecurity ||
		model.DefaultFindingCategory(admin[0].Type, admin[0].Resource.Type) != model.FindingCategorySecurity {
		t.Fatalf("unexpected admin API findings: %#v", admin)
	}

	lifecycle, err := NewPrometheusLifecycleAPIEnabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute lifecycle API analyzer: %v", err)
	}
	if len(lifecycle) != 1 ||
		lifecycle[0].Resource.ID != "lifecycle-enabled" ||
		lifecycle[0].Type != "PrometheusLifecycleAPIEnabled" ||
		lifecycle[0].Severity != model.SeverityWarning ||
		lifecycle[0].Category != model.FindingCategorySecurity ||
		model.DefaultFindingCategory(lifecycle[0].Type, lifecycle[0].Resource.Type) != model.FindingCategorySecurity {
		t.Fatalf("unexpected lifecycle API findings: %#v", lifecycle)
	}

	remoteWrite, err := NewPrometheusRemoteWriteReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute remote-write receiver analyzer: %v", err)
	}
	if len(remoteWrite) != 1 ||
		remoteWrite[0].Resource.ID != "remote-write-enabled" ||
		remoteWrite[0].Type != "PrometheusRemoteWriteReceiverEnabled" ||
		remoteWrite[0].Severity != model.SeverityWarning ||
		remoteWrite[0].Category != model.FindingCategoryConfiguration ||
		model.DefaultFindingCategory(remoteWrite[0].Type, remoteWrite[0].Resource.Type) != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected remote-write receiver findings: %#v", remoteWrite)
	}

	otlp, err := NewPrometheusOTLPReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute OTLP receiver analyzer: %v", err)
	}
	if len(otlp) != 1 ||
		otlp[0].Resource.ID != "otlp-enabled" ||
		otlp[0].Type != "PrometheusOTLPReceiverEnabled" ||
		otlp[0].Severity != model.SeverityWarning ||
		otlp[0].Category != model.FindingCategoryConfiguration ||
		model.DefaultFindingCategory(otlp[0].Type, otlp[0].Resource.Type) != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected OTLP receiver findings: %#v", otlp)
	}
}

func prometheusRuntimeTestResource(id string, reloadSuccess string, corruptionCount string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Source: model.SourceInfo{System: "prometheus", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataPrometheusRuntimeAvailable: "true",
			model.MetadataPrometheusReloadSuccess:    reloadSuccess,
			model.MetadataPrometheusCorruptionCount:  corruptionCount,
			model.MetadataPrometheusLastConfigAt:     "2026-07-25T00:00:00Z",
		},
		Status: model.ResourceStatusActive,
	}
}
