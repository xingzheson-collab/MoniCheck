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
	ComplexNotificationPolicyAnalyzerID     = "builtin.complex_notification_policy"
	defaultNotificationPolicyRouteThreshold = 50
	defaultNotificationPolicyDepthThreshold = 5
)

type ComplexNotificationPolicyAnalyzer struct{}

func NewComplexNotificationPolicyAnalyzer() *ComplexNotificationPolicyAnalyzer {
	return &ComplexNotificationPolicyAnalyzer{}
}

func (a *ComplexNotificationPolicyAnalyzer) ID() string { return ComplexNotificationPolicyAnalyzerID }

func (a *ComplexNotificationPolicyAnalyzer) Name() string { return "Complex Notification Policy" }

func (a *ComplexNotificationPolicyAnalyzer) Version() string { return "0.1.0" }

func (a *ComplexNotificationPolicyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeNotificationPolicy}
}

func (a *ComplexNotificationPolicyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	policies, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeNotificationPolicy})
	if err != nil {
		return nil, err
	}
	routeThreshold := intConfig(analysis.Config, "notification_policy_route_count_threshold", defaultNotificationPolicyRouteThreshold)
	depthThreshold := intConfig(analysis.Config, "notification_policy_depth_threshold", defaultNotificationPolicyDepthThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, policy := range policies {
		if !isActiveNotificationPolicy(policy) {
			continue
		}
		routeCount := notificationPolicyMetadataInt(policy, model.MetadataPolicyRouteCount)
		maxDepth := notificationPolicyMetadataInt(policy, model.MetadataPolicyMaxDepth)
		if routeCount <= routeThreshold && maxDepth <= depthThreshold {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             model.StableID(a.ID(), policy.ID),
			Type:           "ComplexNotificationPolicy",
			Severity:       model.SeverityWarning,
			Resource:       model.ResourceRef{ID: policy.ID, Type: policy.Type, Name: policy.Name},
			Evidence:       []string{fmt.Sprintf("notification policy has %d route nodes and maximum depth %d (thresholds: %d routes, depth %d)", routeCount, maxDepth, routeThreshold, depthThreshold)},
			Recommendation: "拆分或简化通知策略树，合并重复 matcher，减少深层继承和难以审查的路由分支，并在变更后验证关键告警的实际投递路径。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(), "route_count": strconv.Itoa(routeCount), "max_depth": strconv.Itoa(maxDepth),
				"route_count_threshold": strconv.Itoa(routeThreshold), "depth_threshold": strconv.Itoa(depthThreshold),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func notificationPolicyMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(resource.Metadata[key])
	if err != nil || value < 0 {
		return 0
	}
	return value
}
