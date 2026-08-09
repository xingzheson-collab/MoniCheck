package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	UndefinedNotificationPolicyAnalyzerID       = "builtin.undefined_notification_policy"
	NotificationPolicyWithoutReceiverAnalyzerID = "builtin.notification_policy_without_receiver"
	DisabledNotificationPolicyAnalyzerID        = "builtin.disabled_notification_policy"
)

type UndefinedNotificationPolicyAnalyzer struct{}

func NewUndefinedNotificationPolicyAnalyzer() *UndefinedNotificationPolicyAnalyzer {
	return &UndefinedNotificationPolicyAnalyzer{}
}

func (a *UndefinedNotificationPolicyAnalyzer) ID() string {
	return UndefinedNotificationPolicyAnalyzerID
}
func (a *UndefinedNotificationPolicyAnalyzer) Name() string    { return "Undefined Notification Policy" }
func (a *UndefinedNotificationPolicyAnalyzer) Version() string { return "0.1.0" }
func (a *UndefinedNotificationPolicyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *UndefinedNotificationPolicyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if policy.Source.System != "n9e" || policy.Metadata["declared"] != "false" || !notificationPolicyReferencedByRule(policy.ID, analysis) {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "UndefinedNotificationPolicy",
			Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("N9E notification rule %q is referenced by an alert rule but was not discovered", policy.Name)},
			Recommendation: "修正告警规则的 notify_rule_ids，或恢复并启用对应夜莺通知规则，避免告警触发后没有可执行的通知策略。",
			Metadata:       map[string]string{"analyzer_id": a.ID()},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

type NotificationPolicyWithoutReceiverAnalyzer struct{}

func NewNotificationPolicyWithoutReceiverAnalyzer() *NotificationPolicyWithoutReceiverAnalyzer {
	return &NotificationPolicyWithoutReceiverAnalyzer{}
}

type DisabledNotificationPolicyAnalyzer struct{}

func NewDisabledNotificationPolicyAnalyzer() *DisabledNotificationPolicyAnalyzer {
	return &DisabledNotificationPolicyAnalyzer{}
}

func (a *DisabledNotificationPolicyAnalyzer) ID() string { return DisabledNotificationPolicyAnalyzerID }
func (a *DisabledNotificationPolicyAnalyzer) Name() string {
	return "Disabled Referenced Notification Policy"
}
func (a *DisabledNotificationPolicyAnalyzer) Version() string { return "0.1.0" }
func (a *DisabledNotificationPolicyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *DisabledNotificationPolicyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if policy.Source.System != "n9e" || policy.Metadata["declared"] != "true" || n9ePolicyEnabled(policy) || !notificationPolicyReferencedByRule(policy.ID, analysis) {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "DisabledNotificationPolicy",
			Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("disabled N9E notification rule %q is still referenced by an alert rule", policy.Name)},
			Recommendation: "启用并验证该夜莺通知规则，或从告警规则 notify_rule_ids 中移除失效引用并替换为有效通知策略。",
			Metadata:       map[string]string{"analyzer_id": a.ID()},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func (a *NotificationPolicyWithoutReceiverAnalyzer) ID() string {
	return NotificationPolicyWithoutReceiverAnalyzerID
}
func (a *NotificationPolicyWithoutReceiverAnalyzer) Name() string {
	return "Notification Policy Without Receiver"
}
func (a *NotificationPolicyWithoutReceiverAnalyzer) Version() string { return "0.1.0" }
func (a *NotificationPolicyWithoutReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *NotificationPolicyWithoutReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if policy.Source.System != "n9e" || policy.Status != model.ResourceStatusActive || policy.Metadata["declared"] != "true" || !n9ePolicyEnabled(policy) {
			continue
		}
		if notificationPolicyHasReceiver(policy.ID, analysis) {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "NotificationPolicyWithoutReceiver",
			Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("enabled N9E notification rule %q has no valid notification channel relationship", policy.Name)},
			Recommendation: "为夜莺通知规则配置至少一个有效通知媒介和模板，并验证接收人范围；不再使用的空通知规则应禁用或删除。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "route_count": policy.Metadata[model.MetadataPolicyRouteCount]},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func n9ePolicyEnabled(policy model.Resource) bool {
	value := strings.ToLower(strings.TrimSpace(policy.Metadata[model.MetadataEnabled]))
	return value == "" || value == "true" || value == "1" || value == "yes"
}

func notificationPolicyReferencedByRule(policyID string, analysis Context) bool {
	return notificationPolicyReferenced(policyID, analysis, map[string]bool{})
}

func notificationPolicyReferenced(policyID string, analysis Context, visited map[string]bool) bool {
	if visited[policyID] {
		return false
	}
	visited[policyID] = true
	for _, relationship := range analysis.Graph.Incoming(policyID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		resource, ok := analysis.Graph.Resource(relationship.FromID)
		if ok && (resource.Type == model.ResourceTypeAlertRule || resource.Type == model.ResourceTypeRecordingRule) {
			return true
		}
		if ok && resource.Type == model.ResourceTypeNotificationPolicy && resource.Source.System == "n9e" && resource.Metadata["policy_kind"] == "alert_subscription" && resource.Status == model.ResourceStatusActive && n9ePolicyEnabled(resource) {
			return true
		}
	}
	return false
}

func notificationPolicyHasReceiver(policyID string, analysis Context) bool {
	return notificationPolicyReachesReceiver(policyID, analysis, map[string]bool{})
}

func notificationPolicyReachesReceiver(policyID string, analysis Context, visited map[string]bool) bool {
	if visited[policyID] {
		return false
	}
	visited[policyID] = true
	for _, relationship := range analysis.Graph.Outgoing(policyID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		resource, ok := analysis.Graph.Resource(relationship.ToID)
		if ok && resource.Type == model.ResourceTypeReceiver && resource.Status == model.ResourceStatusActive {
			return true
		}
		if ok && resource.Type == model.ResourceTypeNotificationPolicy && resource.Status == model.ResourceStatusActive && n9ePolicyEnabled(resource) && notificationPolicyReachesReceiver(resource.ID, analysis, visited) {
			return true
		}
	}
	return false
}
