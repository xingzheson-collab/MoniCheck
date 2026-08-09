package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
)

const QueryWithoutRecordingRuleAnalyzerID = "builtin.query_without_recording_rule"

const defaultQueryWithoutRecordingRuleLengthThreshold = 200

type QueryWithoutRecordingRuleAnalyzer struct{}

func NewQueryWithoutRecordingRuleAnalyzer() *QueryWithoutRecordingRuleAnalyzer {
	return &QueryWithoutRecordingRuleAnalyzer{}
}

func (a *QueryWithoutRecordingRuleAnalyzer) ID() string {
	return QueryWithoutRecordingRuleAnalyzerID
}

func (a *QueryWithoutRecordingRuleAnalyzer) Name() string {
	return "Query Without Recording Rule"
}

func (a *QueryWithoutRecordingRuleAnalyzer) Version() string {
	return "0.1.0"
}

func (a *QueryWithoutRecordingRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *QueryWithoutRecordingRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	rangeThreshold := durationConfig(analysis.Config, "query_without_recording_rule_range_threshold", defaultWideRangeQueryThreshold)
	lengthThreshold := intConfig(analysis.Config, "query_without_recording_rule_length_threshold", defaultQueryWithoutRecordingRuleLengthThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		if !isRecordingRuleConsumerCandidate(resource.Type) || resource.Status != model.ResourceStatusActive {
			continue
		}
		query := strings.TrimSpace(resource.Metadata[model.MetadataPromQL])
		if query == "" {
			continue
		}
		evidence := queryNeedsRecordingRuleEvidence(query, rangeThreshold, lengthThreshold)
		if len(evidence) == 0 || usesRecordingRuleOutput(resource.ID, analysis) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "QueryWithoutRecordingRule",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence:       evidence,
			Recommendation: "为长窗口或复杂 PromQL 增加 Recording Rule，并让 Dashboard、Panel 或 Alert 直接使用预聚合输出，降低重复查询成本。",
			Metadata: map[string]string{
				"analyzer_id":      a.ID(),
				"range_threshold":  rangeThreshold.String(),
				"length_threshold": fmt.Sprintf("%d", lengthThreshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func isRecordingRuleConsumerCandidate(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule:
		return true
	default:
		return false
	}
}

func queryNeedsRecordingRuleEvidence(query string, rangeThreshold time.Duration, lengthThreshold int) []string {
	evidence := make([]string, 0, 2)
	if duration, ok := maxPromQLRangeDuration(query); ok && duration > rangeThreshold {
		evidence = append(evidence, fmt.Sprintf("PromQL max range selector is %s, threshold is %s", duration, rangeThreshold))
	}
	if len(query) > lengthThreshold {
		evidence = append(evidence, fmt.Sprintf("PromQL length is %d, threshold is %d", len(query), lengthThreshold))
	}
	return evidence
}

func usesRecordingRuleOutput(resourceID string, analysis Context) bool {
	if analysis.Graph == nil {
		return false
	}
	for _, relationship := range analysis.Graph.Outgoing(resourceID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok || target.Type != model.ResourceTypeMetric {
			continue
		}
		if producedByRecordingRule(target.ID, analysis) {
			return true
		}
	}
	return false
}

func producedByRecordingRule(metricID string, analysis Context) bool {
	for _, relationship := range analysis.Graph.Incoming(metricID) {
		if relationship.Type != model.RelationshipProduces {
			continue
		}
		source, ok := analysis.Graph.Resource(relationship.FromID)
		if ok && source.Type == model.ResourceTypeRecordingRule && source.Status == model.ResourceStatusActive {
			return true
		}
	}
	return false
}
