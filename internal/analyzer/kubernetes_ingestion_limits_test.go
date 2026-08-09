package analyzer

import (
	"context"
	"strconv"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesIngestionLimitAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	workload := model.Resource{ID: "workload", UID: "workload", Type: model.ResourceTypeTSDB, Name: "monitoring/main", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Prometheus", "namespace": "monitoring", "prometheus_enforced_ingestion_limit_invalid_setting_count": "1"}}
	unprotected := kubernetesIngestionMonitor("unprotected", 2)
	unprotected.Metadata["monitor_ingestion_limit_invalid_setting_count"] = "2"
	protected := kubernetesIngestionMonitor("protected", 0)
	unselected := kubernetesIngestionMonitor("unselected", 2)
	unselected.Metadata["prometheus_selected_count"] = "0"
	for _, resource := range []model.Resource{workload, unprotected, protected, unselected} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	invalidFindings, err := NewKubernetesIneffectiveIngestionLimitAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(invalidFindings) != 2 {
		t.Fatalf("unexpected invalid limit findings: %#v err=%v", invalidFindings, err)
	}
	tests := []struct {
		name     string
		analyzer Analyzer
		category model.FindingCategory
	}{
		{"sample", NewKubernetesMonitorWithoutSampleLimitAnalyzer(), model.FindingCategoryCost},
		{"target", NewKubernetesMonitorWithoutTargetLimitAnalyzer(), model.FindingCategoryReliability},
		{"label", NewKubernetesMonitorWithoutLabelLimitAnalyzer(), model.FindingCategoryCost},
		{"label length", NewKubernetesMonitorWithoutLabelLengthAnalyzer(), model.FindingCategoryCost},
		{"body", NewKubernetesMonitorWithoutBodySizeLimitAnalyzer(), model.FindingCategorySecurity},
		{"dropped target", NewKubernetesMonitorWithoutDroppedTargetLimitAnalyzer(), model.FindingCategoryCost},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil || len(findings) != 1 || findings[0].Resource.ID != unprotected.ID || findings[0].Category != test.category {
				t.Fatalf("unexpected findings: %#v err=%v", findings, err)
			}
		})
	}
}

func kubernetesIngestionMonitor(name string, unprotected int) model.Resource {
	metadata := map[string]string{
		"kubernetes_kind":           "ServiceMonitor",
		"namespace":                 "monitoring",
		"prometheus_selected_count": "2",
		"monitor_ingestion_limit_invalid_setting_count": "0",
	}
	for _, dimension := range []string{"sample", "target", "label", "label_name_length", "label_value_length", "body", "keep_dropped_targets"} {
		metadata["prometheus_"+dimension+"_limit_unprotected_count"] = strconv.Itoa(unprotected)
	}
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTarget, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: metadata}
}
