package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	HighCardinalityProfileLabelAnalyzerID   = "builtin.high_cardinality_profile_label"
	RiskyProfileLabelAnalyzerID             = "builtin.risky_profile_label"
	defaultProfileLabelValueCountThreshold  = 100
	profileLabelValueCountThresholdConfigID = "profile_label_value_threshold"
)

type HighCardinalityProfileLabelAnalyzer struct{}

func NewHighCardinalityProfileLabelAnalyzer() *HighCardinalityProfileLabelAnalyzer {
	return &HighCardinalityProfileLabelAnalyzer{}
}

func (a *HighCardinalityProfileLabelAnalyzer) ID() string {
	return HighCardinalityProfileLabelAnalyzerID
}

func (a *HighCardinalityProfileLabelAnalyzer) Name() string {
	return "High Cardinality Profile Label"
}

func (a *HighCardinalityProfileLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighCardinalityProfileLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProfileLabel, model.ResourceTypeProfileLabelValue}
}

func (a *HighCardinalityProfileLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeProfileLabel})
	if err != nil {
		return nil, err
	}
	values, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeProfileLabelValue})
	if err != nil {
		return nil, err
	}
	valueCounts := make(map[string]map[string]bool)
	for _, value := range values {
		if value.Status != model.ResourceStatusActive {
			continue
		}
		labelName := strings.TrimSpace(value.Metadata[model.MetadataProfileLabel])
		fingerprint := strings.TrimSpace(value.Metadata[model.MetadataValueFingerprint])
		if labelName == "" || fingerprint == "" {
			continue
		}
		if valueCounts[labelName] == nil {
			valueCounts[labelName] = map[string]bool{}
		}
		valueCounts[labelName][fingerprint] = true
	}

	threshold := intConfig(analysis.Config, profileLabelValueCountThresholdConfigID, defaultProfileLabelValueCountThreshold)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, label := range labels {
		if label.Status != model.ResourceStatusActive {
			continue
		}
		labelName := strings.TrimSpace(label.Metadata[model.MetadataProfileLabel])
		if labelName == "" {
			labelName = strings.TrimSpace(label.Name)
		}
		count := len(valueCounts[labelName])
		if raw := strings.TrimSpace(label.Metadata[model.MetadataProfileLabelValueCount]); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > count {
				count = parsed
			}
		}
		if count <= threshold {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), label.ID, strconv.Itoa(count)),
			Type:     "HighCardinalityProfileLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: label.ID, Type: label.Type, Name: label.Name},
			Evidence: []string{
				fmt.Sprintf("profile label %q has %d discovered values, threshold is %d", labelName, count, threshold),
			},
			Recommendation: "检查 Pyroscope profile label 设计，避免把请求、用户、会话、原始路径或容器实例等高变化维度持续写入 profile series；优先保留稳定服务、环境和版本维度。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"profile_label": labelName,
				"value_count":   strconv.Itoa(count),
				"threshold":     strconv.Itoa(threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

type RiskyProfileLabelAnalyzer struct{}

func NewRiskyProfileLabelAnalyzer() *RiskyProfileLabelAnalyzer {
	return &RiskyProfileLabelAnalyzer{}
}

func (a *RiskyProfileLabelAnalyzer) ID() string {
	return RiskyProfileLabelAnalyzerID
}

func (a *RiskyProfileLabelAnalyzer) Name() string {
	return "Risky Profile Label"
}

func (a *RiskyProfileLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RiskyProfileLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeProfileLabel}
}

func (a *RiskyProfileLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeProfileLabel})
	if err != nil {
		return nil, err
	}
	riskyNames := riskyProfileLabelNameSet(analysis.Config)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, label := range labels {
		if label.Status != model.ResourceStatusActive {
			continue
		}
		labelName := strings.TrimSpace(label.Metadata[model.MetadataProfileLabel])
		if labelName == "" {
			labelName = strings.TrimSpace(label.Name)
		}
		if !riskyNames[normalizeMetricLabelName(labelName)] {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), label.ID),
			Type:     "RiskyProfileLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: label.ID, Type: label.Type, Name: label.Name},
			Evidence: []string{
				fmt.Sprintf("profile label %q commonly carries unbounded or sensitive values", labelName),
			},
			Recommendation: "从持续剖析标签中移除用户、请求、会话、trace/span ID 和原始 URL/path 等无界维度；需要关联单次请求时使用受控的 span profile 关联能力。",
			Metadata: map[string]string{
				"analyzer_id":   a.ID(),
				"profile_label": labelName,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func riskyProfileLabelNameSet(config map[string]any) map[string]bool {
	values := stringSliceConfig(config, "risky_profile_label_names", defaultRiskyMetricLabelNames)
	result := make(map[string]bool, len(values))
	for _, value := range values {
		if normalized := normalizeMetricLabelName(value); normalized != "" {
			result[normalized] = true
		}
	}
	return result
}
