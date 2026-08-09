package analyzer

import (
	"context"
	"fmt"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighCardinalityTraceTagAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	serviceTag := model.Resource{
		ID:     "trace-tag-service",
		Type:   model.ResourceTypeTraceTag,
		Name:   "service.name",
		Status: model.ResourceStatusActive,
	}
	userTag := model.Resource{
		ID:     "trace-tag-user-id",
		Type:   model.ResourceTypeTraceTag,
		Name:   "user.id",
		Status: model.ResourceStatusActive,
	}
	deprecatedTag := model.Resource{
		ID:     "trace-tag-legacy-user",
		Type:   model.ResourceTypeTraceTag,
		Name:   "legacy.user",
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{serviceTag, userTag, deprecatedTag} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert trace tag: %v", err)
		}
	}
	for index, value := range []string{"checkout", "payments"} {
		if err := store.Resources.Upsert(ctx, traceTagValueResource("service.name", value, index)); err != nil {
			t.Fatalf("upsert service tag value: %v", err)
		}
	}
	for index, value := range []string{"legacy-checkout", "legacy-payments"} {
		resource := traceTagValueResource("service.name", value, index+2)
		resource.Status = model.ResourceStatusDeprecated
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert deprecated service tag value: %v", err)
		}
	}
	for index := 0; index < 4; index++ {
		if err := store.Resources.Upsert(ctx, traceTagValueResource("user.id", fmt.Sprintf("user-%d", index), index)); err != nil {
			t.Fatalf("upsert user tag value: %v", err)
		}
	}
	for index := 0; index < 4; index++ {
		if err := store.Resources.Upsert(ctx, traceTagValueResource("legacy.user", fmt.Sprintf("legacy-%d", index), index)); err != nil {
			t.Fatalf("upsert deprecated tag value: %v", err)
		}
	}

	findings, err := NewHighCardinalityTraceTagAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"trace_tag_value_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	finding := findings[0]
	if finding.Resource.ID != userTag.ID || finding.Type != "HighCardinalityTraceTag" || finding.Severity != model.SeverityWarning {
		t.Fatalf("expected high-cardinality finding for user.id tag, got %#v", finding)
	}
	if finding.Metadata["value_count"] != "4" || finding.Metadata["threshold"] != "3" || finding.Metadata["trace_tag"] != "user.id" {
		t.Fatalf("expected value count metadata, got %#v", finding.Metadata)
	}
}

func TestHighCardinalityTraceTagAnalyzerUsesConnectorValueCount(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	tag := model.Resource{
		ID:     "trace-tag-session-id",
		Type:   model.ResourceTypeTraceTag,
		Name:   "session.id",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataTraceTag:           "session.id",
			model.MetadataTraceTagValueCount: "250",
			model.MetadataTruncated:          "true",
		},
	}
	if err := store.Resources.Upsert(ctx, tag); err != nil {
		t.Fatalf("upsert tag: %v", err)
	}
	for index := 0; index < 2; index++ {
		if err := store.Resources.Upsert(ctx, traceTagValueResource("session.id", fmt.Sprintf("session-%d", index), index)); err != nil {
			t.Fatalf("upsert tag value: %v", err)
		}
	}
	findings, err := NewHighCardinalityTraceTagAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"trace_tag_value_threshold": 200},
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

func TestHighCardinalityTraceTagAnalyzerUsesRedactedFingerprints(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	tag := model.Resource{
		ID:     "trace-tag-tenant",
		Type:   model.ResourceTypeTraceTag,
		Name:   "tenant.id",
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, tag); err != nil {
		t.Fatalf("upsert tag: %v", err)
	}
	for index := 0; index < 4; index++ {
		resource := model.Resource{
			ID:     fmt.Sprintf("redacted-trace-value-%d", index),
			Type:   model.ResourceTypeTraceTagValue,
			Name:   fmt.Sprintf("tenant.id=<redacted:%d>", index),
			Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataTraceTag:         "tenant.id",
				model.MetadataValueFingerprint: fmt.Sprintf("fingerprint-%d", index),
				model.MetadataValueRedacted:    "true",
			},
		}
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert redacted tag value: %v", err)
		}
	}
	findings, err := NewHighCardinalityTraceTagAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"trace_tag_value_threshold": 3},
	})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != tag.ID || findings[0].Metadata["value_count"] != "4" {
		t.Fatalf("expected redacted fingerprints to retain cardinality, findings=%#v err=%v", findings, err)
	}
}

func traceTagValueResource(tag string, value string, index int) model.Resource {
	return model.Resource{
		ID:     fmt.Sprintf("trace-tag-value-%s-%d", tag, index),
		Type:   model.ResourceTypeTraceTagValue,
		Name:   tag + "=" + value,
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataTraceTag:      tag,
			model.MetadataTraceTagValue: value,
		},
	}
}
