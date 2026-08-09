package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedRecordingRuleAnalyzerID = "builtin.unused_recording_rule"

type UnusedRecordingRuleAnalyzer struct{}

func NewUnusedRecordingRuleAnalyzer() *UnusedRecordingRuleAnalyzer {
	return &UnusedRecordingRuleAnalyzer{}
}

func (a *UnusedRecordingRuleAnalyzer) ID() string {
	return UnusedRecordingRuleAnalyzerID
}

func (a *UnusedRecordingRuleAnalyzer) Name() string {
	return "Unused Recording Rule"
}

func (a *UnusedRecordingRuleAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnusedRecordingRuleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeRecordingRule}
}

func (a *UnusedRecordingRuleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	recordingRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeRecordingRule})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, recordingRule := range recordingRules {
		if recordingRule.Status != model.ResourceStatusActive {
			continue
		}
		if recordingRuleHasConsumerUsage(recordingRule.ID, analysis) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), recordingRule.ID),
			Type:     "UnusedRecordingRule",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   recordingRule.ID,
				Type: recordingRule.Type,
				Name: recordingRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("recording rule %q has no direct consumer relationship and no consumer of its output metrics", recordingRule.Name),
			},
			Recommendation: "确认该 Recording Rule 的输出是否仍被 Dashboard、Alert 或下游规则使用；若无消费者，可以考虑下线以降低计算成本。",
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

func recordingRuleHasConsumerUsage(recordingRuleID string, analysis Context) bool {
	if hasConsumerUsage(analysis.Graph.Incoming(recordingRuleID)) {
		return true
	}
	for _, relationship := range analysis.Graph.Outgoing(recordingRuleID) {
		if relationship.Type != model.RelationshipProduces {
			continue
		}
		output, ok := analysis.Graph.Resource(relationship.ToID)
		if !ok || output.Type != model.ResourceTypeMetric || output.Status != model.ResourceStatusActive {
			continue
		}
		if hasConsumerUsage(analysis.Graph.Incoming(output.ID)) {
			return true
		}
	}
	return false
}
