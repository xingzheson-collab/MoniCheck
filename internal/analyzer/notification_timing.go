package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	InvalidNotificationTimingAnalyzerID = "builtin.invalid_notification_timing"
	IneffectiveRepeatIntervalAnalyzerID = "builtin.ineffective_repeat_interval"
)

type InvalidNotificationTimingAnalyzer struct{}

func NewInvalidNotificationTimingAnalyzer() *InvalidNotificationTimingAnalyzer {
	return &InvalidNotificationTimingAnalyzer{}
}
func (a *InvalidNotificationTimingAnalyzer) ID() string      { return InvalidNotificationTimingAnalyzerID }
func (a *InvalidNotificationTimingAnalyzer) Name() string    { return "Invalid Notification Timing" }
func (a *InvalidNotificationTimingAnalyzer) Version() string { return "0.1.0" }
func (a *InvalidNotificationTimingAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}
func (a *InvalidNotificationTimingAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return notificationTimingFindings(ctx, analysis, a.ID(), model.MetadataPolicyInvalidTimingCount, "InvalidNotificationTiming", model.SeverityCritical,
		"notification policy contains %d invalid timing setting(s), including unparseable durations or repeat intervals shorter than group intervals",
		"修正 notification policy timing：使用有效 duration，并确保 repeat_interval 大于或等于 group_interval。")
}

type IneffectiveRepeatIntervalAnalyzer struct{}

func NewIneffectiveRepeatIntervalAnalyzer() *IneffectiveRepeatIntervalAnalyzer {
	return &IneffectiveRepeatIntervalAnalyzer{}
}
func (a *IneffectiveRepeatIntervalAnalyzer) ID() string      { return IneffectiveRepeatIntervalAnalyzerID }
func (a *IneffectiveRepeatIntervalAnalyzer) Name() string    { return "Ineffective Repeat Interval" }
func (a *IneffectiveRepeatIntervalAnalyzer) Version() string { return "0.1.0" }
func (a *IneffectiveRepeatIntervalAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}
func (a *IneffectiveRepeatIntervalAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return notificationTimingFindings(ctx, analysis, a.ID(), model.MetadataPolicyRoundedRepeatCount, "IneffectiveRepeatInterval", model.SeverityWarning,
		"notification policy contains %d repeat interval(s) that are not a multiple of the effective group interval and will be rounded by the notification engine",
		"将 repeat_interval 调整为 group_interval 的整数倍，使配置值与实际提醒周期一致。")
}

func notificationTimingFindings(ctx context.Context, analysis Context, analyzerID, metadataKey, findingType string, severity model.Severity, evidence, recommendation string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		count := notificationPolicyMetadataInt(resource, metadataKey)
		if !isActiveNotificationPolicy(resource) || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: []string{fmt.Sprintf(evidence, count)}, Recommendation: recommendation,
			Metadata: map[string]string{"analyzer_id": analyzerID, "timing_issue_count": fmt.Sprintf("%d", count)},
			Status:   model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
