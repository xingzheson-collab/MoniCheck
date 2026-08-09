package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighImpactMetricAnalyzerID                = "builtin.high_impact_metric"
	defaultHighImpactMetricConsumerThreshold  = 5
	defaultHighImpactMetricConsumerNameSample = 5
)

type HighImpactMetricAnalyzer struct{}

func NewHighImpactMetricAnalyzer() *HighImpactMetricAnalyzer {
	return &HighImpactMetricAnalyzer{}
}

func (a *HighImpactMetricAnalyzer) ID() string {
	return HighImpactMetricAnalyzerID
}

func (a *HighImpactMetricAnalyzer) Name() string {
	return "High Impact Metric"
}

func (a *HighImpactMetricAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighImpactMetricAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeMetric}
}

func (a *HighImpactMetricAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	metrics, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeMetric})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, "high_impact_metric_consumer_threshold", defaultHighImpactMetricConsumerThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, metric := range metrics {
		if metric.Status != model.ResourceStatusActive {
			continue
		}
		consumers := metricConsumers(metric.ID, analysis)
		if len(consumers) <= threshold {
			continue
		}

		consumerNames := sampledConsumerNames(consumers, defaultHighImpactMetricConsumerNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), metric.ID),
			Type:     "HighImpactMetric",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   metric.ID,
				Type: metric.Type,
				Name: metric.Name,
			},
			Evidence: []string{
				fmt.Sprintf("metric %q has %d downstream consumers, threshold is %d", metric.Name, len(consumers), threshold),
				fmt.Sprintf("sample consumers: %s", strings.Join(consumerNames, ", ")),
			},
			Recommendation: "将该指标纳入变更保护清单；修改采集、命名或标签前先评估 Dashboard、Alert 和 Recording Rule 的影响面。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"consumer_count": strconv.Itoa(len(consumers)),
				"threshold":      strconv.Itoa(threshold),
				"consumers":      strings.Join(consumerNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func metricConsumers(metricID string, analysis Context) []model.Resource {
	seen := make(map[string]bool)
	consumers := make([]model.Resource, 0)
	metricIDs := downstreamMetricIDs(metricID, analysis)
	for _, currentMetricID := range metricIDs {
		for _, relationship := range analysis.Graph.Incoming(currentMetricID) {
			if !isConsumerRelationship(relationship.Type) || seen[relationship.FromID] {
				continue
			}
			consumer, ok := analysis.Graph.Resource(relationship.FromID)
			if !ok || consumer.Status != model.ResourceStatusActive {
				continue
			}
			if !isMetricConsumerResource(consumer.Type) {
				continue
			}
			seen[consumer.ID] = true
			consumers = append(consumers, consumer)
		}
	}
	sortResourcesByTypeAndName(consumers)
	return consumers
}

func downstreamMetricIDs(metricID string, analysis Context) []string {
	seen := map[string]bool{metricID: true}
	queue := []string{metricID}
	result := make([]string, 0, 1)
	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		result = append(result, currentID)
		for _, relationship := range analysis.Graph.Outgoing(currentID) {
			if relationship.Type != model.RelationshipProduces {
				continue
			}
			if seen[relationship.ToID] {
				continue
			}
			target, ok := analysis.Graph.Resource(relationship.ToID)
			if !ok || target.Type != model.ResourceTypeMetric || target.Status != model.ResourceStatusActive {
				continue
			}
			seen[relationship.ToID] = true
			queue = append(queue, relationship.ToID)
		}
	}
	return result
}

func isConsumerRelationship(relationshipType model.RelationshipType) bool {
	switch relationshipType {
	case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
		return true
	default:
		return false
	}
}

func isMetricConsumerResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule:
		return true
	default:
		return false
	}
}

func sampledConsumerNames(consumers []model.Resource, limit int) []string {
	if limit <= 0 || len(consumers) <= limit {
		return resourceNames(consumers)
	}
	names := resourceNames(consumers[:limit])
	names = append(names, fmt.Sprintf("+%d more", len(consumers)-limit))
	return names
}

func resourceNames(resources []model.Resource) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		names = append(names, fmt.Sprintf("%s/%s", resource.Type, resource.Name))
	}
	return names
}
