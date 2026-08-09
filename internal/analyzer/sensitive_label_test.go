package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSensitiveLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	cleanMetric := model.Resource{
		ID:     "metric-clean",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Labels: map[string]string{"service": "api"},
		Metadata: map[string]string{
			"plugin_id":                                        "safe-plugin",
			"alertmanager_automount_token_declared":            "true",
			"alertmanager_automount_token_enabled":             "false",
			"alertmanager_automount_token_valid":               "true",
			"prometheus_automount_token_declared":              "true",
			"prometheus_automount_token_enabled":               "false",
			"prometheus_automount_token_valid":                 "true",
			"prometheus_image_pull_secret_count":               "1",
			"prometheus_image_pull_secrets_declared":           "true",
			"prometheus_secret_count":                          "2",
			"prometheus_secrets_declared":                      "true",
			"thanos_ruler_image_pull_secret_count":             "1",
			"thanos_ruler_image_pull_secrets_declared":         "true",
			"thanos_ruler_secret_config_metadata":              "true",
			"thanos_ruler_secret_selector_declared_count":      "2",
			"thanos_ruler_secret_config_invalid_setting_count": "0",
			"thanos_ruler_shadowed_secret_config_count":        "1",
		},
		Status: model.ResourceStatusActive,
	}
	leakyAlert := model.Resource{
		ID:     "alert-secret",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LeakyAlert",
		Labels: map[string]string{"api_token": "do-not-report-value"},
		Metadata: map[string]string{
			"db_password": "do-not-report-value",
		},
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{cleanMetric, leakyAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewSensitiveLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "SensitiveLabel" || findings[0].Resource.ID != leakyAlert.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].Metadata["sensitive_keys"] != "label.api_token,metadata.db_password" {
		t.Fatalf("unexpected sensitive keys: %#v", findings[0].Metadata)
	}
	for _, evidence := range findings[0].Evidence {
		if evidence == "do-not-report-value" {
			t.Fatalf("evidence leaked sensitive value")
		}
	}
}

func TestSensitiveLabelAnalyzerCustomKeys(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{
		ID:       "target-custom",
		Type:     model.ResourceTypeTarget,
		Name:     "target",
		Labels:   map[string]string{"tenant_secret_name": "expected-by-custom-policy"},
		Metadata: map[string]string{"owner": "platform"},
		Status:   model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewSensitiveLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"sensitive_label_keys": "tenant_secret"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != resource.ID {
		t.Fatalf("expected finding for %s, got %#v", resource.ID, findings)
	}
}

func TestSensitiveLabelAnalyzerDetectsLokiLabelNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	secretLabel := model.Resource{
		ID:     "log-label-token",
		Type:   model.ResourceTypeLogLabel,
		Name:   "api_token",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLogLabel: "api_token",
		},
	}
	secretValue := model.Resource{
		ID:     "log-label-value-password",
		Type:   model.ResourceTypeLogLabelValue,
		Name:   "password=do-not-report-value",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLogLabel:      "password",
			model.MetadataLogLabelValue: "do-not-report-value",
		},
	}
	cleanLabel := model.Resource{
		ID:     "log-label-app",
		Type:   model.ResourceTypeLogLabel,
		Name:   "app",
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{secretLabel, secretValue, cleanLabel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewSensitiveLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	found := map[string]model.Finding{}
	for _, finding := range findings {
		found[finding.Resource.ID] = finding
		if strings.Contains(finding.Resource.Name, "do-not-report-value") {
			t.Fatalf("resource ref leaked sensitive log label value: %#v", finding.Resource)
		}
		for _, evidence := range finding.Evidence {
			if strings.Contains(evidence, "do-not-report-value") {
				t.Fatalf("evidence leaked sensitive log label value: %q", evidence)
			}
		}
	}
	if found[secretLabel.ID].Metadata["sensitive_keys"] != "log_label.api_token" {
		t.Fatalf("expected sensitive log label name, got %#v", found[secretLabel.ID].Metadata)
	}
	if found[secretValue.ID].Metadata["sensitive_keys"] != "log_label.password" {
		t.Fatalf("expected sensitive log label value label name, got %#v", found[secretValue.ID].Metadata)
	}
}

func TestSensitiveLabelAnalyzerDetectsMetricLabelNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "metric-label-secret", Type: model.ResourceTypeMetricLabel, Name: "api_token", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabel: "api_token"}},
		{ID: "metric-label-safe", Type: model.ResourceTypeMetricLabel, Name: "service", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabel: "service"}},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewSensitiveLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != "metric-label-secret" || findings[0].Metadata["sensitive_keys"] != "metric_label.api_token" {
		t.Fatalf("expected sensitive metric label finding, got %#v", findings)
	}
}

func TestSensitiveLabelAnalyzerDetectsTempoTraceTagNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	secretTag := model.Resource{
		ID:     "trace-tag-token",
		Type:   model.ResourceTypeTraceTag,
		Name:   "api.token",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataTraceTag: "api.token",
		},
	}
	secretValue := model.Resource{
		ID:     "trace-tag-value-password",
		Type:   model.ResourceTypeTraceTagValue,
		Name:   "password=do-not-report-value",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataTraceTag:      "password",
			model.MetadataTraceTagValue: "do-not-report-value",
		},
	}
	cleanTag := model.Resource{
		ID:     "trace-tag-service",
		Type:   model.ResourceTypeTraceTag,
		Name:   "service.name",
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{secretTag, secretValue, cleanTag} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewSensitiveLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	found := map[string]model.Finding{}
	for _, finding := range findings {
		found[finding.Resource.ID] = finding
		if strings.Contains(finding.Resource.Name, "do-not-report-value") {
			t.Fatalf("resource ref leaked sensitive trace tag value: %#v", finding.Resource)
		}
		for _, evidence := range finding.Evidence {
			if strings.Contains(evidence, "do-not-report-value") {
				t.Fatalf("evidence leaked sensitive trace tag value: %q", evidence)
			}
		}
	}
	if found[secretTag.ID].Metadata["sensitive_keys"] != "trace_tag.api.token" {
		t.Fatalf("expected sensitive trace tag name, got %#v", found[secretTag.ID].Metadata)
	}
	if found[secretValue.ID].Metadata["sensitive_keys"] != "trace_tag.password" {
		t.Fatalf("expected sensitive trace tag value tag name, got %#v", found[secretValue.ID].Metadata)
	}
}
