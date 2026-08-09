package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	NotificationFanoutRiskAnalyzerID                = "builtin.notification_fanout_risk"
	defaultNotificationPolicyContinueRouteThreshold = 5
)

type NotificationFanoutRiskAnalyzer struct{}

func NewNotificationFanoutRiskAnalyzer() *NotificationFanoutRiskAnalyzer {
	return &NotificationFanoutRiskAnalyzer{}
}

func (a *NotificationFanoutRiskAnalyzer) ID() string      { return NotificationFanoutRiskAnalyzerID }
func (a *NotificationFanoutRiskAnalyzer) Name() string    { return "Notification Fanout Risk" }
func (a *NotificationFanoutRiskAnalyzer) Version() string { return "0.1.0" }
func (a *NotificationFanoutRiskAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *NotificationFanoutRiskAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	threshold := intConfig(analysis.Config, "notification_policy_continue_route_threshold", defaultNotificationPolicyContinueRouteThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if !isActiveNotificationPolicy(policy) {
			continue
		}
		continueCount := notificationPolicyMetadataInt(policy, model.MetadataPolicyContinueRouteCount)
		catchAllContinue := notificationPolicyMetadataInt(policy, model.MetadataPolicyCatchAllContinueCount)
		if continueCount <= threshold && catchAllContinue == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "NotificationFanoutRisk", Severity: model.SeverityWarning,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("notification policy has %d continue routes, including %d matcherless continue routes (threshold %d)", continueCount, catchAllContinue, threshold)},
			Recommendation: "复核 continue 路由是否确需向多个同级接收端重复投递；为无条件 continue 路由增加 matcher，并通过测试告警确认不会产生重复通知风暴。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(), "continue_route_count": strconv.Itoa(continueCount),
				"catch_all_continue_count": strconv.Itoa(catchAllContinue), "continue_route_threshold": strconv.Itoa(threshold),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
