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
	PrometheusDebugLoggingAnalyzerID                          = "builtin.prometheus_debug_logging"
	PrometheusLongAutoReloadIntervalAnalyzerID                = "builtin.prometheus_long_auto_reload_interval"
	PrometheusHighNotificationSubscriberLimitAnalyzerID       = "builtin.prometheus_high_notification_subscriber_limit"
	prometheusDefaultAutoReloadIntervalSeconds          int64 = 30
	prometheusDefaultNotificationSubscriberLimit        int64 = 16
)

type PrometheusOperationalRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusDebugLoggingAnalyzer() *PrometheusOperationalRuntimeAnalyzer {
	return &PrometheusOperationalRuntimeAnalyzer{id: PrometheusDebugLoggingAnalyzerID, name: "Prometheus Debug Logging"}
}

func NewPrometheusLongAutoReloadIntervalAnalyzer() *PrometheusOperationalRuntimeAnalyzer {
	return &PrometheusOperationalRuntimeAnalyzer{id: PrometheusLongAutoReloadIntervalAnalyzerID, name: "Prometheus Long Auto Reload Interval"}
}

func NewPrometheusHighNotificationSubscriberLimitAnalyzer() *PrometheusOperationalRuntimeAnalyzer {
	return &PrometheusOperationalRuntimeAnalyzer{id: PrometheusHighNotificationSubscriberLimitAnalyzerID, name: "Prometheus High Notification Subscriber Limit"}
}

func (a *PrometheusOperationalRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusOperationalRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusOperationalRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusOperationalRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusOperationalRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusOperationalRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryCost
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusDebugLoggingAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusLogLevel] != "debug" {
			return model.Finding{}, false
		}
		findingType = "PrometheusDebugLogging"
		evidence = "Prometheus runtime log level is explicitly set to debug"
		recommendation = "故障排查结束后将 --log.level 恢复到官方 info 默认值或 warn，并为临时 debug 日志设置采集限额、短保留期和访问控制。"
		metadata[model.MetadataPrometheusLogLevel] = "debug"
	case PrometheusLongAutoReloadIntervalAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusConfigAutoReloadEnabled] != "true" {
			return model.Finding{}, false
		}
		seconds, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusAutoReloadIntervalSeconds)
		if !ok || seconds <= prometheusDefaultAutoReloadIntervalSeconds {
			return model.Finding{}, false
		}
		findingType = "PrometheusLongAutoReloadInterval"
		category = model.FindingCategoryReliability
		evidence = fmt.Sprintf("Prometheus automatic configuration reload interval is %d seconds, above the official default of 30 seconds", seconds)
		recommendation = "将 --config.auto-reload-interval 恢复到官方 30s 默认值或经过变更生效目标验证的更短窗口，并监控 reload success 与最后成功配置时间。"
		metadata[model.MetadataPrometheusAutoReloadIntervalSeconds] = strconv.FormatInt(seconds, 10)
	case PrometheusHighNotificationSubscriberLimitAnalyzerID:
		limit, ok := prometheusNonNegativeMetadataInt64(resource, model.MetadataPrometheusMaxNotificationSubscribers)
		if !ok || limit <= prometheusDefaultNotificationSubscriberLimit {
			return model.Finding{}, false
		}
		findingType = "PrometheusHighNotificationSubscriberLimit"
		evidence = fmt.Sprintf("Prometheus live notification subscriber limit is %d, above the official default of 16", limit)
		recommendation = "将 --web.max-notifications-subscribers 恢复到官方 16 默认值或经过连接、内存和事件广播压测验证的范围，并通过认证代理限制 UI/API 访问。"
		metadata[model.MetadataPrometheusMaxNotificationSubscribers] = strconv.FormatInt(limit, 10)
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
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
