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
	DatadogMonitorNoDataAnalyzerID                              = "builtin.datadog_monitor_no_data"
	DatadogMonitorUnknownAnalyzerID                             = "builtin.datadog_monitor_unknown"
	DatadogMonitorWithoutServiceAnalyzerID                      = "builtin.datadog_monitor_without_service"
	DatadogMonitorWithoutPriorityAnalyzerID                     = "builtin.datadog_monitor_without_priority"
	DatadogMonitorWithoutRunbookAnalyzerID                      = "builtin.datadog_monitor_without_runbook"
	DatadogMonitorWithoutRenotifyAnalyzerID                     = "builtin.datadog_monitor_without_renotify"
	DatadogPriorityMonitorWithoutNoDataNotificationAnalyzerID   = "builtin.datadog_priority_monitor_without_no_data_notification"
	DatadogPriorityMonitorWithoutNotificationCoverageAnalyzerID = "builtin.datadog_priority_monitor_without_notification_coverage"
	DatadogPriorityMetricMonitorWithoutRecoveryAnalyzerID       = "builtin.datadog_priority_metric_monitor_without_recovery_threshold"
	DatadogServiceWithoutTeamAnalyzerID                         = "builtin.datadog_service_without_team"
)

type DatadogGovernanceAnalyzer struct {
	id           string
	name         string
	kind         string
	resourceType model.ResourceType
}

func NewDatadogMonitorNoDataAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorNoDataAnalyzerID, "Datadog Monitor No Data", "no_data", model.ResourceTypeAlertRule)
}

func NewDatadogMonitorUnknownAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorUnknownAnalyzerID, "Datadog Monitor Unknown", "unknown", model.ResourceTypeAlertRule)
}

func NewDatadogMonitorWithoutServiceAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorWithoutServiceAnalyzerID, "Datadog Monitor Without Service", "missing_service", model.ResourceTypeAlertRule)
}

func NewDatadogMonitorWithoutPriorityAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorWithoutPriorityAnalyzerID, "Datadog Monitor Without Priority", "missing_priority", model.ResourceTypeAlertRule)
}

func NewDatadogMonitorWithoutRunbookAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorWithoutRunbookAnalyzerID, "Datadog Priority Monitor Without Runbook", "missing_runbook", model.ResourceTypeAlertRule)
}

func NewDatadogMonitorWithoutRenotifyAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogMonitorWithoutRenotifyAnalyzerID, "Datadog Priority Monitor Without Renotify", "missing_renotify", model.ResourceTypeAlertRule)
}

func NewDatadogPriorityMonitorWithoutNoDataNotificationAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogPriorityMonitorWithoutNoDataNotificationAnalyzerID, "Datadog Priority Monitor Without No-Data Notification", "missing_no_data_notification", model.ResourceTypeAlertRule)
}

func NewDatadogPriorityMonitorWithoutNotificationCoverageAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogPriorityMonitorWithoutNotificationCoverageAnalyzerID, "Datadog Priority Monitor Without Notification Coverage", "missing_notification_coverage", model.ResourceTypeAlertRule)
}

func NewDatadogPriorityMetricMonitorWithoutRecoveryAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogPriorityMetricMonitorWithoutRecoveryAnalyzerID, "Datadog Priority Metric Monitor Without Recovery Threshold", "missing_recovery_threshold", model.ResourceTypeAlertRule)
}

func NewDatadogServiceWithoutTeamAnalyzer() *DatadogGovernanceAnalyzer {
	return newDatadogGovernanceAnalyzer(DatadogServiceWithoutTeamAnalyzerID, "Datadog Service Without Team", "missing_team", model.ResourceTypeService)
}

func newDatadogGovernanceAnalyzer(id, name, kind string, resourceType model.ResourceType) *DatadogGovernanceAnalyzer {
	return &DatadogGovernanceAnalyzer{id: id, name: name, kind: kind, resourceType: resourceType}
}

func (a *DatadogGovernanceAnalyzer) ID() string      { return a.id }
func (a *DatadogGovernanceAnalyzer) Name() string    { return a.name }
func (a *DatadogGovernanceAnalyzer) Version() string { return "0.1.0" }
func (a *DatadogGovernanceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{a.resourceType}
}

func (a *DatadogGovernanceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: a.resourceType})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *DatadogGovernanceAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	if resource.Status != model.ResourceStatusActive || resource.Source.System != "datadog" {
		return model.Finding{}, false
	}
	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.ID()}

	switch a.kind {
	case "no_data":
		if resource.Metadata[model.MetadataDatadogMonitor] != "true" ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataDatadogOverallState]), "No Data") {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		category = model.FindingCategoryReliability
		findingType = "DatadogMonitorNoData"
		evidence = fmt.Sprintf("Datadog monitor %q currently reports the explicit No Data state", resource.Name)
		recommendation = "检查采集链路、查询范围和缺失数据策略；恢复可评估数据，并确认关键 monitor 的 no-data 通知符合值班要求。"
		metadata["overall_state"] = "No Data"
	case "unknown":
		if resource.Metadata[model.MetadataDatadogMonitor] != "true" ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataDatadogOverallState]), "Unknown") {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "DatadogMonitorUnknown"
		evidence = fmt.Sprintf("Datadog monitor %q currently reports the explicit Unknown state", resource.Name)
		recommendation = "检查 monitor 查询、数据源权限、公式依赖和最近配置变更；恢复为可解释的 OK、Warn 或 Alert 状态。"
		metadata["overall_state"] = "Unknown"
	case "missing_service":
		if resource.Metadata[model.MetadataDatadogMonitor] != "true" ||
			resource.Metadata[model.MetadataDatadogServiceTagDeclared] == "true" {
			return model.Finding{}, false
		}
		findingType = "DatadogMonitorWithoutService"
		evidence = fmt.Sprintf("Datadog monitor %q has no service tag", resource.Name)
		recommendation = "为 monitor 增加统一的 service:<name> tag，使告警能够关联 Service Catalog、负责人和影响范围。"
	case "missing_priority":
		if resource.Metadata[model.MetadataDatadogMonitor] != "true" ||
			resource.Metadata[model.MetadataDatadogPriorityDeclared] == "true" {
			return model.Finding{}, false
		}
		findingType = "DatadogMonitorWithoutPriority"
		evidence = fmt.Sprintf("Datadog monitor %q has no native P1-P5 priority", resource.Name)
		recommendation = "为 monitor 声明符合组织分级标准的 Datadog P1-P5 priority，并将优先级映射到通知、升级和响应时限。"
	case "missing_runbook":
		priority, ok := datadogHighPriority(resource)
		if !ok || resource.Metadata[model.MetadataDatadogRunbookConfigured] == "true" {
			return model.Finding{}, false
		}
		findingType = "DatadogPriorityMonitorWithoutRunbook"
		evidence = fmt.Sprintf("Datadog priority %d monitor %q has no runbook asset", priority, resource.Name)
		recommendation = "为高优先级 monitor 绑定 Datadog runbook asset，覆盖诊断入口、止血步骤、升级路径和恢复验证。"
		metadata["priority"] = strconv.Itoa(priority)
	case "missing_renotify":
		priority, ok := datadogHighPriority(resource)
		interval, _ := strconv.Atoi(resource.Metadata[model.MetadataDatadogRenotifyInterval])
		if !ok || interval > 0 {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "DatadogPriorityMonitorWithoutRenotify"
		evidence = fmt.Sprintf("Datadog priority %d monitor %q has no positive renotify interval", priority, resource.Name)
		recommendation = "为需要持续响应的高优先级 monitor 配置经过值班验证的 renotify interval 和次数，避免长期未恢复事件失去可见性。"
		metadata["priority"] = strconv.Itoa(priority)
	case "missing_no_data_notification":
		priority, ok := datadogHighPriority(resource)
		if !ok ||
			resource.Metadata[model.MetadataDatadogNoDataNotificationEvaluable] != "true" ||
			resource.Metadata[model.MetadataDatadogNoDataNotificationConfigured] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "DatadogPriorityMonitorWithoutNoDataNotification"
		evidence = fmt.Sprintf("Datadog priority %d monitor %q is configured not to notify when evaluation data is missing", priority, resource.Name)
		recommendation = "为高优先级 monitor 将 on_missing_data 设为 show_and_notify_no_data，或在 legacy 配置中启用 notify_no_data，并验证断流通知能够到达值班链路。"
		metadata["priority"] = strconv.Itoa(priority)
	case "missing_notification_coverage":
		priority, ok := datadogHighPriority(resource)
		if !ok ||
			resource.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] != "true" ||
			resource.Metadata[model.MetadataDatadogNotificationCoverageConfigured] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "DatadogPriorityMonitorWithoutNotificationCoverage"
		evidence = fmt.Sprintf("Datadog priority %d monitor %q has neither a direct notification recipient nor a matching evaluable notification rule", priority, resource.Name)
		recommendation = "在 monitor message 中配置有效 @recipient，或创建可匹配该 monitor tag 的 Notification Rule，并通过测试告警验证值班接收链路。"
		metadata["priority"] = strconv.Itoa(priority)
	case "missing_recovery_threshold":
		priority, ok := datadogHighPriority(resource)
		if !ok ||
			!strings.EqualFold(strings.TrimSpace(resource.Metadata[model.MetadataDatadogMonitorType]), "metric alert") ||
			resource.Metadata[model.MetadataDatadogCriticalRecoveryEvaluable] != "true" ||
			resource.Metadata[model.MetadataDatadogCriticalRecoveryConfigured] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "DatadogPriorityMetricMonitorWithoutRecoveryThreshold"
		evidence = fmt.Sprintf("Datadog priority %d metric monitor %q has no explicit critical recovery threshold", priority, resource.Name)
		recommendation = "为高优先级 metric monitor 配置经过验证的 critical_recovery 阈值；公式型 monitor 可使用受支持的 critical recovery query，并验证恢复区间能够抑制阈值附近的告警抖动。"
		metadata["priority"] = strconv.Itoa(priority)
	case "missing_team":
		if resource.Metadata[model.MetadataDatadogServiceDefinition] != "true" ||
			resource.Metadata[model.MetadataDatadogTeamDeclared] == "true" {
			return model.Finding{}, false
		}
		category = model.FindingCategoryLifecycle
		findingType = "DatadogServiceWithoutTeam"
		evidence = fmt.Sprintf("Datadog service definition %q has no team ownership", resource.Name)
		recommendation = "在 Datadog Service Definition 中声明 team，并确保团队目录、值班和升级路径保持有效。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.ID(), resource.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       category,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func datadogHighPriority(resource model.Resource) (int, bool) {
	if resource.Metadata[model.MetadataDatadogMonitor] != "true" ||
		resource.Metadata[model.MetadataDatadogPriorityDeclared] != "true" {
		return 0, false
	}
	priority, err := strconv.Atoi(resource.Metadata[model.MetadataDatadogPriority])
	return priority, err == nil && priority >= 1 && priority <= 2
}
