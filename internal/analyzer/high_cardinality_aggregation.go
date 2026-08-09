package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/prometheus/promql/parser"

	"monicheck/internal/model"
)

const HighCardinalityAggregationAnalyzerID = "builtin.high_cardinality_aggregation"

const defaultAggregationLabelThreshold = 3

type HighCardinalityAggregationAnalyzer struct{}

func NewHighCardinalityAggregationAnalyzer() *HighCardinalityAggregationAnalyzer {
	return &HighCardinalityAggregationAnalyzer{}
}

func (a *HighCardinalityAggregationAnalyzer) ID() string {
	return HighCardinalityAggregationAnalyzerID
}

func (a *HighCardinalityAggregationAnalyzer) Name() string {
	return "High Cardinality Aggregation"
}

func (a *HighCardinalityAggregationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighCardinalityAggregationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *HighCardinalityAggregationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	threshold := intConfig(analysis.Config, "aggregation_label_threshold", defaultAggregationLabelThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		labels, ok := maxAggregationGrouping(query)
		if !ok || len(labels) <= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "HighCardinalityAggregation",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("PromQL aggregation groups by %d labels (%s), threshold is %d", len(labels), strings.Join(labels, ","), threshold),
			},
			Recommendation: "减少 PromQL 聚合的 by 标签数量，优先按业务必要维度聚合；高维度分组建议改用 Recording Rule 预聚合或拆分视图。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"grouping_labels": strings.Join(labels, ","),
				"threshold":       fmt.Sprintf("%d", threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func maxAggregationGrouping(query string) ([]string, bool) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return nil, false
	}
	var maxLabels []string
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		aggregate, ok := node.(*parser.AggregateExpr)
		if !ok || aggregate.Without || len(aggregate.Grouping) <= len(maxLabels) {
			return nil
		}
		maxLabels = append([]string(nil), aggregate.Grouping...)
		return nil
	})
	return maxLabels, len(maxLabels) > 0
}
