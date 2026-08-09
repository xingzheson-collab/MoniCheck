package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const NotificationGroupingDisabledAnalyzerID = "builtin.notification_grouping_disabled"

type NotificationGroupingDisabledAnalyzer struct{}

func NewNotificationGroupingDisabledAnalyzer() *NotificationGroupingDisabledAnalyzer {
	return &NotificationGroupingDisabledAnalyzer{}
}
func (a *NotificationGroupingDisabledAnalyzer) ID() string {
	return NotificationGroupingDisabledAnalyzerID
}
func (a *NotificationGroupingDisabledAnalyzer) Name() string    { return "Notification Grouping Disabled" }
func (a *NotificationGroupingDisabledAnalyzer) Version() string { return "0.1.0" }
func (a *NotificationGroupingDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *NotificationGroupingDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		count := notificationPolicyMetadataInt(resource, model.MetadataPolicyUngroupedRouteCount)
		if !isActiveNotificationPolicy(resource) || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "NotificationGroupingDisabled", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("notification policy has %d route(s) using group_by ['...'], which sends each distinct alert label set as a separate notification group", count)},
			Recommendation: "使用 alertname、service、team、cluster 或 namespace 等稳定标签进行分组；仅在下游系统负责聚合或告警量极低时保留 `...`。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "ungrouped_route_count": strconv.Itoa(count)},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
