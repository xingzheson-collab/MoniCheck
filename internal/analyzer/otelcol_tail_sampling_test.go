package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelTailSamplingAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	missing := otelTailSamplingTestResource("tail_sampling/missing", "0", "true", "0")
	invalid := otelTailSamplingTestResource("tail_sampling/invalid", "1", "true", "1")
	valid := otelTailSamplingTestResource("tail_sampling/valid", "2", "true", "0")
	dynamic := otelTailSamplingTestResource("tail_sampling/dynamic", "", "false", "0")
	unused := otelTailSamplingTestResource("tail_sampling/unused", "0", "true", "1")
	wrongSource := otelTailSamplingTestResource("tail_sampling/wrong-source", "0", "true", "1")
	fullCapture := otelTailSamplingTestResource("tail_sampling/full-capture", "2", "true", "0")
	fullCapture.Metadata[model.MetadataOTelTailSamplingFullCapture] = "true"
	dropPending := otelTailSamplingTestResource("tail_sampling/drop-pending", "1", "true", "0")
	dropPending.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] = "true"
	dynamicDropPending := otelTailSamplingTestResource("tail_sampling/dynamic-drop-pending", "1", "true", "0")
	dynamicDropPending.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] = "false"
	dynamicDropPending.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] = "true"
	zeroCapacity := otelTailSamplingTestResource("tail_sampling/zero-capacity", "1", "true", "0")
	zeroCapacity.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] = "true"
	dynamicCapacity := otelTailSamplingTestResource("tail_sampling/dynamic-capacity", "1", "true", "0")
	dynamicCapacity.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] = "false"
	dynamicCapacity.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] = "true"
	undersizedCache := otelTailSamplingTestResource("tail_sampling/undersized-cache", "1", "true", "0")
	undersizedCache.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] = "2"
	dynamicCache := otelTailSamplingTestResource("tail_sampling/dynamic-cache", "1", "true", "0")
	dynamicCache.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] = "false"
	dynamicCache.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] = "1"
	tailStorageGateDisabled := otelTailSamplingTestResource("tail_sampling/tail-storage-gate-disabled", "1", "true", "0")
	tailStorageGateDisabled.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageGateDisabled.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] = "true"
	tailStorageGateDisabled.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled] = "false"
	tailStorageGateUnknown := otelTailSamplingTestResource("tail_sampling/tail-storage-gate-unknown", "1", "true", "0")
	tailStorageGateUnknown.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageGateEnabled := otelTailSamplingTestResource("tail_sampling/tail-storage-gate-enabled", "1", "true", "0")
	tailStorageGateEnabled.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageGateEnabled.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] = "true"
	tailStorageGateEnabled.Metadata[model.MetadataOTelTailSamplingTailStorageGateEnabled] = "true"
	tailStorageExtensionUnavailable := otelTailSamplingTestResource("tail_sampling/tail-storage-extension-unavailable", "1", "true", "0")
	tailStorageExtensionUnavailable.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageExtensionUnavailable.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] = "true"
	tailStorageExtensionUnavailable.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady] = "false"
	tailStorageExtensionUnknown := otelTailSamplingTestResource("tail_sampling/tail-storage-extension-unknown", "1", "true", "0")
	tailStorageExtensionUnknown.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageExtensionReady := otelTailSamplingTestResource("tail_sampling/tail-storage-extension-ready", "1", "true", "0")
	tailStorageExtensionReady.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "true"
	tailStorageExtensionReady.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] = "true"
	tailStorageExtensionReady.Metadata[model.MetadataOTelTailSamplingTailStorageExtensionReady] = "true"
	unboundedTraceSize := otelTailSamplingTestResource("tail_sampling/unbounded-trace-size", "1", "true", "0")
	unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] = "true"
	unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] = "true"
	unboundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] = "true"
	boundedTraceSize := otelTailSamplingTestResource("tail_sampling/bounded-trace-size", "1", "true", "0")
	boundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] = "true"
	boundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] = "true"
	boundedTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeUnbounded] = "false"
	dynamicTraceSize := otelTailSamplingTestResource("tail_sampling/dynamic-trace-size", "1", "true", "0")
	dynamicTraceSize.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] = "true"
	overflowEviction := otelTailSamplingTestResource("tail_sampling/overflow-eviction", "1", "true", "0")
	overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] = "true"
	overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] = "true"
	overflowEviction.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] = "false"
	overflowBlocking := otelTailSamplingTestResource("tail_sampling/overflow-blocking", "1", "true", "0")
	overflowBlocking.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] = "true"
	overflowBlocking.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] = "true"
	overflowBlocking.Metadata[model.MetadataOTelTailSamplingBlockOverflowEnabled] = "true"
	dynamicOverflow := otelTailSamplingTestResource("tail_sampling/dynamic-overflow", "1", "true", "0")
	dynamicOverflow.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] = "true"
	policyAttributionEnabled := otelTailSamplingTestResource("tail_sampling/policy-attribution-enabled", "1", "true", "0")
	policyAttributionEnabled.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] = "true"
	policyAttributionEnabled.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled] = "true"
	policyAttributionDisabled := otelTailSamplingTestResource("tail_sampling/policy-attribution-disabled", "1", "true", "0")
	policyAttributionDisabled.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] = "true"
	policyAttributionDisabled.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEnabled] = "false"
	policyAttributionUnknown := otelTailSamplingTestResource("tail_sampling/policy-attribution-unknown", "1", "true", "0")
	detailedMetricsEnabled := otelTailSamplingTestResource("tail_sampling/detailed-metrics-enabled", "1", "true", "0")
	detailedMetricsEnabled.Metadata[model.MetadataOTelTailSamplingDetailedMetricsEnabledCnt] = "2"
	detailedMetricsDisabled := otelTailSamplingTestResource("tail_sampling/detailed-metrics-disabled", "1", "true", "0")
	dynamic.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] = "false"
	delete(dynamic.Metadata, model.MetadataOTelTailSamplingFullCapture)
	unused.Metadata[model.MetadataOTelTailSamplingFullCapture] = "true"
	wrongSource.Metadata[model.MetadataOTelTailSamplingFullCapture] = "true"
	wrongSource.Source.System = "plugin"
	inactive := otelTailSamplingTestResource("tail_sampling/inactive", "0", "true", "1")
	inactive.Metadata[model.MetadataOTelTailSamplingFullCapture] = "true"
	inactive.Status = model.ResourceStatusDeprecated
	unmarked := otelResource(model.ResourceTypeProcessor, "attributes", "processor:attributes")

	for _, resource := range []model.Resource{pipeline, missing, invalid, valid, dynamic, unused, wrongSource, inactive, fullCapture, dropPending, dynamicDropPending, zeroCapacity, dynamicCapacity, undersizedCache, dynamicCache, tailStorageGateDisabled, tailStorageGateUnknown, tailStorageGateEnabled, tailStorageExtensionUnavailable, tailStorageExtensionUnknown, tailStorageExtensionReady, unboundedTraceSize, boundedTraceSize, dynamicTraceSize, overflowEviction, overflowBlocking, dynamicOverflow, policyAttributionEnabled, policyAttributionDisabled, policyAttributionUnknown, detailedMetricsEnabled, detailedMetricsDisabled, unmarked} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, processor := range []model.Resource{missing, invalid, valid, dynamic, wrongSource, inactive, fullCapture, dropPending, dynamicDropPending, zeroCapacity, dynamicCapacity, undersizedCache, dynamicCache, tailStorageGateDisabled, tailStorageGateUnknown, tailStorageGateEnabled, tailStorageExtensionUnavailable, tailStorageExtensionUnknown, tailStorageExtensionReady, unboundedTraceSize, boundedTraceSize, dynamicTraceSize, overflowEviction, overflowBlocking, dynamicOverflow, policyAttributionEnabled, policyAttributionDisabled, policyAttributionUnknown, detailedMetricsEnabled, detailedMetricsDisabled, unmarked} {
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     "pipeline-uses-" + processor.ID,
			FromID: pipeline.ID,
			ToID:   processor.ID,
			Type:   model.RelationshipUses,
		}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	tests := []struct {
		analyzer     Analyzer
		resourceID   string
		findingType  string
		evidencePart string
		severity     model.Severity
		category     model.FindingCategory
	}{
		{NewOTelTailSamplingWithoutPolicyAnalyzer(), missing.ID, "OTelTailSamplingWithoutPolicy", "no evaluable sampling policy", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelTailSamplingInvalidConfigAnalyzer(), invalid.ID, "OTelTailSamplingInvalidConfig", "1 explicit structural", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelTailSamplingFullCaptureAnalyzer(), fullCapture.ID, "OTelTailSamplingFullCapture", "deterministically retains every trace", model.SeverityWarning, model.FindingCategoryCost},
		{NewOTelTailSamplingDropPendingAnalyzer(), dropPending.ID, "OTelTailSamplingDropsPendingOnShutdown", "drops pending traces", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOTelTailSamplingZeroTraceCapacityAnalyzer(), zeroCapacity.ID, "OTelTailSamplingZeroTraceCapacity", "zero in-memory trace capacity", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOTelTailSamplingUndersizedDecisionCacheAnalyzer(), undersizedCache.ID, "OTelTailSamplingUndersizedDecisionCache", "2 enabled decision cache", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOTelTailSamplingTailStorageGateDisabledAnalyzer(), tailStorageGateDisabled.ID, "OTelTailSamplingTailStorageGateDisabled", "required feature gate is explicitly disabled", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelTailSamplingTailStorageExtensionUnavailableAnalyzer(), tailStorageExtensionUnavailable.ID, "OTelTailSamplingTailStorageExtensionUnavailable", "not both declared and enabled", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelTailSamplingUnboundedTraceSizeAnalyzer(), unboundedTraceSize.ID, "OTelTailSamplingUnboundedTraceSize", "disables early dropping", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOTelTailSamplingOverflowEvictionEnabledAnalyzer(), overflowEviction.ID, "OTelTailSamplingOverflowEvictionEnabled", "evicts old traces", model.SeverityWarning, model.FindingCategoryReliability},
		{NewOTelTailSamplingPolicyAttributionEnabledAnalyzer(), policyAttributionEnabled.ID, "OTelTailSamplingPolicyAttributionEnabled", "policy attribution enabled", model.SeverityWarning, model.FindingCategoryCost},
		{NewOTelTailSamplingDetailedMetricsEnabledAnalyzer(), detailedMetricsEnabled.ID, "OTelTailSamplingDetailedMetricsEnabled", "2 alpha detailed sampling metric", model.SeverityWarning, model.FindingCategoryCost},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != test.severity ||
				findings[0].Category != test.category ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected tail-sampling findings: %#v", findings)
			}
			encoded, err := json.Marshal(findings[0])
			if err != nil {
				t.Fatalf("marshal finding: %v", err)
			}
			for _, privateValue := range []string{"private-policy", "private-attribute", "future-strategy"} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("finding leaked %q: %s", privateValue, encoded)
				}
			}
		})
	}
}

func otelTailSamplingTestResource(name, policyCount, policiesEvaluable, issueCount string) model.Resource {
	resource := otelResource(model.ResourceTypeProcessor, name, "processor:"+name)
	resource.Metadata[model.MetadataComponentKind] = "processor"
	resource.Metadata[model.MetadataComponentType] = "tail_sampling"
	resource.Metadata[model.MetadataOTelTailSamplingConfig] = "true"
	resource.Metadata[model.MetadataOTelTailSamplingPoliciesEvaluable] = policiesEvaluable
	if policyCount != "" {
		resource.Metadata[model.MetadataOTelTailSamplingPolicyCount] = policyCount
	}
	resource.Metadata[model.MetadataOTelTailSamplingConfigIssueCount] = issueCount
	resource.Metadata[model.MetadataOTelTailSamplingFullCaptureEvaluable] = "true"
	resource.Metadata[model.MetadataOTelTailSamplingFullCapture] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingDropPendingEvaluable] = "true"
	resource.Metadata[model.MetadataOTelTailSamplingDropPendingOnShutdown] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingTraceCapacityEvaluable] = "true"
	resource.Metadata[model.MetadataOTelTailSamplingZeroTraceCapacity] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingDecisionCacheEvaluable] = "true"
	resource.Metadata[model.MetadataOTelTailSamplingUndersizedDecisionCacheCnt] = "0"
	resource.Metadata[model.MetadataOTelTailSamplingTailStorageConfigured] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingTailStorageGateEvaluable] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingTailStorageRefEvaluable] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeConfigured] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingMaxTraceSizeEvaluable] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingBlockOverflowConfigured] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingBlockOverflowEvaluable] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingRecordPolicyGateEvaluable] = "false"
	resource.Metadata[model.MetadataOTelTailSamplingDetailedMetricsEnabledCnt] = "0"
	return resource
}
