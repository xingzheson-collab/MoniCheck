package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusZeroNotificationQueueCapacityAnalyzerID = "builtin.prometheus_zero_notification_queue_capacity"
	PrometheusNotificationQueueNotDrainedAnalyzerID   = "builtin.prometheus_notification_queue_not_drained"
	PrometheusShortAlertResendDelayAnalyzerID         = "builtin.prometheus_short_alert_resend_delay"
	PrometheusLargeNotificationBatchSizeAnalyzerID    = "builtin.prometheus_large_notification_batch_size"
)

type PrometheusNotificationQueueAnalyzer struct {
	id   string
	name string
}

func NewPrometheusZeroNotificationQueueCapacityAnalyzer() *PrometheusNotificationQueueAnalyzer {
	return &PrometheusNotificationQueueAnalyzer{
		id:   PrometheusZeroNotificationQueueCapacityAnalyzerID,
		name: "Prometheus Zero Notification Queue Capacity",
	}
}

func NewPrometheusNotificationQueueNotDrainedAnalyzer() *PrometheusNotificationQueueAnalyzer {
	return &PrometheusNotificationQueueAnalyzer{
		id:   PrometheusNotificationQueueNotDrainedAnalyzerID,
		name: "Prometheus Notification Queue Not Drained",
	}
}

func NewPrometheusShortAlertResendDelayAnalyzer() *PrometheusNotificationQueueAnalyzer {
	return &PrometheusNotificationQueueAnalyzer{
		id:   PrometheusShortAlertResendDelayAnalyzerID,
		name: "Prometheus Short Alert Resend Delay",
	}
}

func NewPrometheusLargeNotificationBatchSizeAnalyzer() *PrometheusNotificationQueueAnalyzer {
	return &PrometheusNotificationQueueAnalyzer{
		id:   PrometheusLargeNotificationBatchSizeAnalyzerID,
		name: "Prometheus Large Notification Batch Size",
	}
}

func (a *PrometheusNotificationQueueAnalyzer) ID() string      { return a.id }
func (a *PrometheusNotificationQueueAnalyzer) Name() string    { return a.name }
func (a *PrometheusNotificationQueueAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusNotificationQueueAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusNotificationQueueAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataRulesDiscoveryAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAgentMode] == "true" {
			continue
		}
		alertingRules := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataAlertingRuleCount)
		activeAlertmanagers := prometheusDeliveryMetadataInt(resource.Metadata, model.MetadataPrometheusActiveAMCount)
		if alertingRules <= 0 || activeAlertmanagers <= 0 {
			continue
		}
		if finding, ok := a.finding(resource, alertingRules, activeAlertmanagers, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusNotificationQueueAnalyzer) finding(resource model.Resource, alertingRules int, activeAlertmanagers int, now time.Time) (model.Finding, bool) {
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{
		"analyzer_id":                         a.id,
		model.MetadataAlertingRuleCount:       strconv.Itoa(alertingRules),
		model.MetadataPrometheusActiveAMCount: strconv.Itoa(activeAlertmanagers),
	}

	switch a.id {
	case PrometheusZeroNotificationQueueCapacityAnalyzerID:
		capacity, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusNotificationQueueCapacity)
		if !ok || capacity != 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusZeroNotificationQueueCapacity"
		evidence = fmt.Sprintf("Prometheus has %d alerting rule(s) and %d active Alertmanager target(s), but the pending notification queue capacity is 0", alertingRules, activeAlertmanagers)
		recommendation = "将 --alertmanager.notification-queue-capacity 设置为经过告警峰值验证的正整数，并观察通知队列长度、丢弃和发送失败指标。"
		metadata[model.MetadataPrometheusNotificationQueueCapacity] = "0"
	case PrometheusNotificationQueueNotDrainedAnalyzerID:
		drain, ok := resource.Metadata[model.MetadataPrometheusDrainNotificationQueue]
		if !ok || drain != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusNotificationQueueNotDrained"
		evidence = fmt.Sprintf("Prometheus has %d alerting rule(s) and %d active Alertmanager target(s), but queued notifications are not drained on shutdown", alertingRules, activeAlertmanagers)
		recommendation = "启用 --alertmanager.drain-notification-queue-on-shutdown，并为滚动升级和终止流程预留足够的优雅退出时间。"
		metadata[model.MetadataPrometheusDrainNotificationQueue] = "false"
	case PrometheusShortAlertResendDelayAnalyzerID:
		delay, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusAlertResendDelay)
		if !ok || delay <= 0 || delay >= 60 {
			return model.Finding{}, false
		}
		findingType = "PrometheusShortAlertResendDelay"
		evidence = fmt.Sprintf("Prometheus has %d alerting rule(s) and %d active Alertmanager target(s), but resends active alerts after only %d seconds, below the official 60-second default", alertingRules, activeAlertmanagers, delay)
		recommendation = "将 --rules.alert.resend-delay 恢复到官方 1m 默认值或经过告警吞吐压测验证的更长间隔，并观察 Alertmanager 接收、重试和错误指标。"
		metadata[model.MetadataPrometheusAlertResendDelay] = strconv.FormatInt(delay, 10)
	case PrometheusLargeNotificationBatchSizeAnalyzerID:
		batchSize, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusNotificationBatchSize)
		if !ok || batchSize <= 256 {
			return model.Finding{}, false
		}
		findingType = "PrometheusLargeNotificationBatchSize"
		evidence = fmt.Sprintf("Prometheus has %d alerting rule(s) and %d active Alertmanager target(s), but sends up to %d alerts per notification batch, above the official 256-alert default", alertingRules, activeAlertmanagers, batchSize)
		recommendation = "将 --alertmanager.notification-batch-size 恢复到官方 256 默认值或经过端到端压测验证的上限，并观察请求大小、发送延迟、失败与重试。"
		metadata[model.MetadataPrometheusNotificationBatchSize] = strconv.FormatInt(batchSize, 10)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
