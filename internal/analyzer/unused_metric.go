package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedMetricAnalyzerID = "builtin.unused_metric"

type UnusedMetricAnalyzer struct{}

func NewUnusedMetricAnalyzer() *UnusedMetricAnalyzer {
	return &UnusedMetricAnalyzer{}
}

func (a *UnusedMetricAnalyzer) ID() string {
	return UnusedMetricAnalyzerID
}

func (a *UnusedMetricAnalyzer) Name() string {
	return "Unused Metric"
}

func (a *UnusedMetricAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnusedMetricAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *UnusedMetricAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if metric.Status != model.ResourceStatusActive {
			continue
		}
		if metricHasActiveConsumer(metric.ID, analysis) {
			continue
		}

		id := model.StableID(a.ID(), metric.ID)
		findings = append(findings, model.Finding{
			ID:       id,
			Type:     "UnusedMetric",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   metric.ID,
				Type: metric.Type,
				Name: metric.Name,
			},
			Evidence: []string{
				fmt.Sprintf("metric %q has no incoming resource relationship", metric.Name),
			},
			Recommendation: "Confirm whether the metric still has operational value. If no dashboard, alert, or recording rule depends on it, stop collecting it or mark it deprecated after an owner review.",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func metricHasActiveConsumer(metricID string, analysis Context) bool {
	for _, relationship := range analysis.Graph.Incoming(metricID) {
		if !isConsumerRelationship(relationship.Type) {
			continue
		}
		consumer, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || consumer.Status != model.ResourceStatusActive {
			continue
		}
		if isMetricConsumerResource(consumer.Type) {
			return true
		}
	}
	return false
}

func hasConsumerUsage(relationships []model.Relationship) bool {
	for _, relationship := range relationships {
		switch relationship.Type {
		case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
			return true
		}
	}
	return false
}
