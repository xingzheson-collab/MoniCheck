package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const ShadowedNotificationRouteAnalyzerID = "builtin.shadowed_notification_route"

type ShadowedNotificationRouteAnalyzer struct{}

func NewShadowedNotificationRouteAnalyzer() *ShadowedNotificationRouteAnalyzer {
	return &ShadowedNotificationRouteAnalyzer{}
}

func (a *ShadowedNotificationRouteAnalyzer) ID() string      { return ShadowedNotificationRouteAnalyzerID }
func (a *ShadowedNotificationRouteAnalyzer) Name() string    { return "Shadowed Notification Route" }
func (a *ShadowedNotificationRouteAnalyzer) Version() string { return "0.1.0" }
func (a *ShadowedNotificationRouteAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *ShadowedNotificationRouteAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if !isActiveNotificationPolicy(policy) {
			continue
		}
		shadowed := notificationPolicyMetadataInt(policy, model.MetadataPolicyShadowedRouteCount)
		if shadowed == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), policy.ID), Type: "ShadowedNotificationRoute", Severity: model.SeverityCritical,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("notification policy has %d route nodes shadowed by an earlier matcherless sibling with continue=false", shadowed)},
			Recommendation: "为无条件子路由增加明确 matcher、将其移动到同级分支末尾，或在确需继续匹配时显式启用 continue，并用代表性告警验证每条投递路径。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "shadowed_route_count": strconv.Itoa(shadowed)},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
