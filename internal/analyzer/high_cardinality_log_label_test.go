package analyzer

import (
	"context"
	"fmt"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighCardinalityLogLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	appLabel := model.Resource{
		ID:     "log-label-app",
		Type:   model.ResourceTypeLogLabel,
		Name:   "app",
		Status: model.ResourceStatusActive,
	}
	userLabel := model.Resource{
		ID:     "log-label-user-id",
		Type:   model.ResourceTypeLogLabel,
		Name:   "user_id",
		Status: model.ResourceStatusActive,
	}
	deprecatedLabel := model.Resource{
		ID:     "log-label-legacy-user",
		Type:   model.ResourceTypeLogLabel,
		Name:   "legacy_user",
		Status: model.ResourceStatusDeprecated,
	}
	if err := store.Resources.Upsert(ctx, appLabel); err != nil {
		t.Fatalf("upsert app label: %v", err)
	}
	if err := store.Resources.Upsert(ctx, userLabel); err != nil {
		t.Fatalf("upsert user label: %v", err)
	}
	if err := store.Resources.Upsert(ctx, deprecatedLabel); err != nil {
		t.Fatalf("upsert deprecated label: %v", err)
	}
	for index, value := range []string{"checkout", "payments"} {
		if err := store.Resources.Upsert(ctx, logLabelValueResource("app", value, index)); err != nil {
			t.Fatalf("upsert app label value: %v", err)
		}
	}
	for index, value := range []string{"legacy-checkout", "legacy-payments"} {
		resource := logLabelValueResource("app", value, index+2)
		resource.Status = model.ResourceStatusDeprecated
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert deprecated app label value: %v", err)
		}
	}
	for index := 0; index < 4; index++ {
		if err := store.Resources.Upsert(ctx, logLabelValueResource("user_id", fmt.Sprintf("user-%d", index), index)); err != nil {
			t.Fatalf("upsert user label value: %v", err)
		}
	}
	for index := 0; index < 4; index++ {
		if err := store.Resources.Upsert(ctx, logLabelValueResource("legacy_user", fmt.Sprintf("legacy-%d", index), index)); err != nil {
			t.Fatalf("upsert deprecated label value: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewHighCardinalityLogLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"log_label_value_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	finding := findings[0]
	if finding.Resource.ID != userLabel.ID || finding.Type != "HighCardinalityLogLabel" || finding.Severity != model.SeverityWarning {
		t.Fatalf("expected high-cardinality finding for user_id label, got %#v", finding)
	}
	if finding.Metadata["value_count"] != "4" || finding.Metadata["threshold"] != "3" || finding.Metadata["label"] != "user_id" {
		t.Fatalf("expected value count metadata, got %#v", finding.Metadata)
	}
}

func TestHighCardinalityLogLabelAnalyzerUsesConnectorValueCount(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	label := model.Resource{
		ID:     "log-label-session-id",
		Type:   model.ResourceTypeLogLabel,
		Name:   "session_id",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLogLabel:           "session_id",
			model.MetadataLogLabelValueCount: "250",
			model.MetadataTruncated:          "true",
		},
	}
	if err := store.Resources.Upsert(ctx, label); err != nil {
		t.Fatalf("upsert label: %v", err)
	}
	for index := 0; index < 2; index++ {
		if err := store.Resources.Upsert(ctx, logLabelValueResource("session_id", fmt.Sprintf("session-%d", index), index)); err != nil {
			t.Fatalf("upsert label value: %v", err)
		}
	}
	findings, err := NewHighCardinalityLogLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"log_label_value_threshold": 200},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from connector value count, got %#v", findings)
	}
	if findings[0].Metadata["value_count"] != "250" || findings[0].Metadata["threshold"] != "200" {
		t.Fatalf("expected connector value count metadata, got %#v", findings[0].Metadata)
	}
}

func TestHighCardinalityLogLabelAnalyzerUsesRedactedFingerprints(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	label := model.Resource{
		ID:     "log-label-tenant",
		Type:   model.ResourceTypeLogLabel,
		Name:   "tenant",
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, label); err != nil {
		t.Fatalf("upsert label: %v", err)
	}
	for index := 0; index < 4; index++ {
		resource := model.Resource{
			ID:     fmt.Sprintf("redacted-log-value-%d", index),
			Type:   model.ResourceTypeLogLabelValue,
			Name:   fmt.Sprintf("tenant=<redacted:%d>", index),
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataLogLabel:         "tenant",
				model.MetadataValueFingerprint: fmt.Sprintf("fingerprint-%d", index),
				model.MetadataValueRedacted:    "true",
			},
		}
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert redacted label value: %v", err)
		}
	}
	findings, err := NewHighCardinalityLogLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"log_label_value_threshold": 3},
	})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != label.ID || findings[0].Metadata["value_count"] != "4" {
		t.Fatalf("expected redacted fingerprints to retain cardinality, findings=%#v err=%v", findings, err)
	}
}

func logLabelValueResource(label string, value string, index int) model.Resource {
	return model.Resource{
		ID:     fmt.Sprintf("log-label-value-%s-%d", label, index),
		Type:   model.ResourceTypeLogLabelValue,
		Name:   label + "=" + value,
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLogLabel:      label,
			model.MetadataLogLabelValue: value,
		},
	}
}
