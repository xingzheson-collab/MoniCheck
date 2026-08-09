package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BroadAlertSubscriptionAnalyzerID = "builtin.broad_alert_subscription"

type BroadAlertSubscriptionAnalyzer struct{}

func NewBroadAlertSubscriptionAnalyzer() *BroadAlertSubscriptionAnalyzer {
	return &BroadAlertSubscriptionAnalyzer{}
}

func (a *BroadAlertSubscriptionAnalyzer) ID() string      { return BroadAlertSubscriptionAnalyzerID }
func (a *BroadAlertSubscriptionAnalyzer) Name() string    { return "Broad N9E Alert Subscription" }
func (a *BroadAlertSubscriptionAnalyzer) Version() string { return "0.1.0" }
func (a *BroadAlertSubscriptionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *BroadAlertSubscriptionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		metadata := policy.Metadata
		if policy.Source.System != "n9e" || policy.Status != model.ResourceStatusActive || metadata["policy_kind"] != "alert_subscription" || !n9ePolicyEnabled(policy) {
			continue
		}
		if metadata["subscription_rule_filter_count"] != "0" || metadata["subscription_tag_matcher_count"] != "0" || metadata["subscription_group_matcher_count"] != "0" || metadata["datasource_scope"] != "all" || metadata["product"] != "" || metadata["category"] != "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "BroadAlertSubscription",
			Severity: model.SeverityWarning, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("enabled N9E alert subscription %q matches all rules, datasources, products, categories, tags, and business groups", policy.Name)},
			Recommendation: "为夜莺告警订阅增加明确的 rule_ids、数据源、产品/类别、标签或业务组匹配条件，并验证订阅不会把无关告警扩散到接收团队。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "project": metadata["project"]},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
