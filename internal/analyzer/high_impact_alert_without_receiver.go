package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighImpactAlertWithoutReceiverAnalyzerID  = "builtin.high_impact_alert_without_receiver"
	defaultHighImpactAlertInstanceThreshold   = 3
	defaultHighImpactAlertInstanceNameSample  = 5
	highImpactAlertInstanceThresholdConfigKey = "high_impact_alert_instance_threshold"
)

type HighImpactAlertWithoutReceiverAnalyzer struct{}

func NewHighImpactAlertWithoutReceiverAnalyzer() *HighImpactAlertWithoutReceiverAnalyzer {
	return &HighImpactAlertWithoutReceiverAnalyzer{}
}

func (a *HighImpactAlertWithoutReceiverAnalyzer) ID() string {
	return HighImpactAlertWithoutReceiverAnalyzerID
}

func (a *HighImpactAlertWithoutReceiverAnalyzer) Name() string {
	return "High Impact Alert Without Receiver"
}

func (a *HighImpactAlertWithoutReceiverAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighImpactAlertWithoutReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlertRule}
}

func (a *HighImpactAlertWithoutReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alertRules, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlertRule})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, highImpactAlertInstanceThresholdConfigKey, defaultHighImpactAlertInstanceThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alertRule := range alertRules {
		if alertRule.Status != model.ResourceStatusActive || isDisabledAlert(alertRule) {
			continue
		}

		instances := activeAlertInstancesForRule(alertRule.ID, analysis)
		if len(instances) <= threshold {
			continue
		}

		missingReceiver := alertInstancesWithoutReceiver(instances)
		if len(missingReceiver) == 0 {
			continue
		}

		sampleNames := sampledConsumerNames(missingReceiver, defaultHighImpactAlertInstanceNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alertRule.ID),
			Type:     "HighImpactAlertWithoutReceiver",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   alertRule.ID,
				Type: alertRule.Type,
				Name: alertRule.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alert rule %q has %d active alert instances, threshold is %d", alertRule.Name, len(instances), threshold),
				fmt.Sprintf("%d active alert instances have no receiver names", len(missingReceiver)),
				fmt.Sprintf("sample alerts without receiver: %s", strings.Join(sampleNames, ", ")),
			},
			Recommendation: "优先修复该高影响告警规则的 Alertmanager 路由；确认 labels 能匹配有效 route，并确保 firing 告警至少进入一个真实 receiver。",
			Metadata: map[string]string{
				"analyzer_id":                     a.ID(),
				"active_alert_instance_count":     strconv.Itoa(len(instances)),
				"missing_receiver_instance_count": strconv.Itoa(len(missingReceiver)),
				"threshold":                       strconv.Itoa(threshold),
				"alerts_without_receiver":         strings.Join(sampleNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func activeAlertInstancesForRule(ruleID string, analysis Context) []model.Resource {
	seen := make(map[string]bool)
	instances := make([]model.Resource, 0)
	for _, relationship := range analysis.Graph.Incoming(ruleID) {
		if relationship.Type != model.RelationshipReferences || seen[relationship.FromID] {
			continue
		}
		alert, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || alert.Type != model.ResourceTypeAlert || alert.Status != model.ResourceStatusActive {
			continue
		}
		if !isActiveAlertInstance(alert) {
			continue
		}
		seen[alert.ID] = true
		instances = append(instances, alert)
	}
	sortResourcesByTypeAndName(instances)
	return instances
}

func alertInstancesWithoutReceiver(alerts []model.Resource) []model.Resource {
	missing := make([]model.Resource, 0)
	for _, alert := range alerts {
		if strings.TrimSpace(alert.Metadata[model.MetadataReceiverNames]) != "" {
			continue
		}
		missing = append(missing, alert)
	}
	return missing
}

func isActiveAlertInstance(alert model.Resource) bool {
	state := strings.ToLower(strings.TrimSpace(alert.Metadata[model.MetadataAlertState]))
	return state == "" || state == "active" || state == "firing" || state == "pending"
}
