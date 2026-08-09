package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const SensitiveLabelAnalyzerID = "builtin.sensitive_label"

var defaultSensitiveLabelKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_key",
	"access_token",
	"private_key",
	"credential",
}

var ignoredSensitiveLabelKeys = map[string]bool{
	"analyzer_id":                                      true,
	"plugin_id":                                        true,
	"plugin_version":                                   true,
	"request_id":                                       true,
	"dashboard_uid":                                    true,
	"datasource_uid":                                   true,
	"folder_uid":                                       true,
	"panel_id":                                         true,
	"fingerprint":                                      true,
	"generator_url":                                    true,
	"runbook_url":                                      true,
	"allowed_severity":                                 true,
	"alertmanager_automount_token_declared":            true,
	"alertmanager_automount_token_enabled":             true,
	"alertmanager_automount_token_valid":               true,
	"alertmanager_config_secret_configured":            true,
	"alertmanager_config_secret_declared":              true,
	"alertmanager_config_secret_valid":                 true,
	"alertmanager_image_pull_secret_count":             true,
	"alertmanager_image_pull_secrets_declared":         true,
	"alertmanager_secret_count":                        true,
	"alertmanager_secrets_declared":                    true,
	"prometheus_automount_token_declared":              true,
	"prometheus_automount_token_enabled":               true,
	"prometheus_automount_token_valid":                 true,
	"prometheus_image_pull_secret_count":               true,
	"prometheus_image_pull_secrets_declared":           true,
	"prometheus_secret_count":                          true,
	"prometheus_secrets_declared":                      true,
	"thanos_ruler_image_pull_secret_count":             true,
	"thanos_ruler_image_pull_secrets_declared":         true,
	"thanos_ruler_secret_config_metadata":              true,
	"thanos_ruler_secret_selector_declared_count":      true,
	"thanos_ruler_secret_config_invalid_setting_count": true,
	"thanos_ruler_shadowed_secret_config_count":        true,
}

type SensitiveLabelAnalyzer struct{}

func NewSensitiveLabelAnalyzer() *SensitiveLabelAnalyzer {
	return &SensitiveLabelAnalyzer{}
}

func (a *SensitiveLabelAnalyzer) ID() string {
	return SensitiveLabelAnalyzerID
}

func (a *SensitiveLabelAnalyzer) Name() string {
	return "Sensitive Label"
}

func (a *SensitiveLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *SensitiveLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeMetric,
		model.ResourceTypeMetricLabel,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeDatasource,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeExporter,
		model.ResourceTypeJob,
		model.ResourceTypeInstance,
		model.ResourceTypeLogLabel,
		model.ResourceTypeLogLabelValue,
		model.ResourceTypeTraceTag,
		model.ResourceTypeTraceTagValue,
	}
}

func (a *SensitiveLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}

	patterns := sensitiveLabelPatterns(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, resource := range resources {
		keys := sensitiveResourceKeys(resource, patterns)
		if len(keys) == 0 {
			continue
		}
		resourceName := sensitiveResourceDisplayName(resource)

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID, strings.Join(keys, ",")),
			Type:     "SensitiveLabel",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resourceName,
			},
			Evidence: []string{
				fmt.Sprintf("%s %q contains sensitive label/metadata keys: %s", resource.Type, resourceName, strings.Join(keys, ", ")),
			},
			Recommendation: "不要在监控资源 labels 或 metadata 中保存密码、token、密钥等敏感信息；请迁移到受控 Secret 管理系统并清理历史数据。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"sensitive_keys": strings.Join(keys, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func sensitiveLabelPatterns(config map[string]any) []string {
	values := stringSliceConfig(config, "sensitive_label_keys", defaultSensitiveLabelKeys)
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func sensitiveResourceKeys(resource model.Resource, patterns []string) []string {
	keys := make([]string, 0)
	seen := map[string]bool{}
	add := func(key string) {
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range resource.Labels {
		if isSensitiveKey(key, patterns) {
			add("label." + key)
		}
	}
	for key := range resource.Metadata {
		if isSensitiveKey(key, patterns) {
			add("metadata." + key)
		}
	}
	switch resource.Type {
	case model.ResourceTypeMetricLabel:
		for _, labelName := range []string{resource.Name, resource.Metadata[model.MetadataMetricLabel]} {
			if labelName = strings.TrimSpace(labelName); labelName != "" && isSensitiveKey(labelName, patterns) {
				add("metric_label." + labelName)
			}
		}
	case model.ResourceTypeLogLabel:
		for _, labelName := range []string{resource.Name, resource.Metadata[model.MetadataLogLabel]} {
			if labelName = strings.TrimSpace(labelName); labelName != "" && isSensitiveKey(labelName, patterns) {
				add("log_label." + labelName)
			}
		}
	case model.ResourceTypeLogLabelValue:
		labelName := strings.TrimSpace(resource.Metadata[model.MetadataLogLabel])
		if labelName == "" {
			labelName = logLabelNameFromSensitiveValueResource(resource.Name)
		}
		if labelName != "" && isSensitiveKey(labelName, patterns) {
			add("log_label." + labelName)
		}
	case model.ResourceTypeTraceTag:
		for _, tagName := range []string{resource.Name, resource.Metadata[model.MetadataTraceTag]} {
			if tagName = strings.TrimSpace(tagName); tagName != "" && isSensitiveKey(tagName, patterns) {
				add("trace_tag." + tagName)
			}
		}
	case model.ResourceTypeTraceTagValue:
		tagName := strings.TrimSpace(resource.Metadata[model.MetadataTraceTag])
		if tagName == "" {
			tagName = logLabelNameFromSensitiveValueResource(resource.Name)
		}
		if tagName != "" && isSensitiveKey(tagName, patterns) {
			add("trace_tag." + tagName)
		}
	}
	sort.Strings(keys)
	return keys
}

func sensitiveResourceDisplayName(resource model.Resource) string {
	if resource.Type != model.ResourceTypeLogLabelValue && resource.Type != model.ResourceTypeTraceTagValue {
		return resource.Name
	}
	labelName := strings.TrimSpace(resource.Metadata[model.MetadataLogLabel])
	if resource.Type == model.ResourceTypeTraceTagValue {
		labelName = strings.TrimSpace(resource.Metadata[model.MetadataTraceTag])
	}
	if labelName == "" {
		labelName = logLabelNameFromSensitiveValueResource(resource.Name)
	}
	if labelName == "" {
		return "<redacted>"
	}
	return labelName + "=<redacted>"
}

func logLabelNameFromSensitiveValueResource(name string) string {
	index := strings.Index(name, "=")
	if index <= 0 {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(name[:index])
}

func isSensitiveKey(key string, patterns []string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" || ignoredSensitiveLabelKeys[normalized] {
		return false
	}
	for _, pattern := range patterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}
	return false
}
