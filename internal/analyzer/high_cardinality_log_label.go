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
	HighCardinalityLogLabelAnalyzerID   = "builtin.high_cardinality_log_label"
	defaultLogLabelValueCountThreshold  = 100
	logLabelValueCountThresholdConfigID = "log_label_value_threshold"
)

type HighCardinalityLogLabelAnalyzer struct{}

func NewHighCardinalityLogLabelAnalyzer() *HighCardinalityLogLabelAnalyzer {
	return &HighCardinalityLogLabelAnalyzer{}
}

func (a *HighCardinalityLogLabelAnalyzer) ID() string {
	return HighCardinalityLogLabelAnalyzerID
}

func (a *HighCardinalityLogLabelAnalyzer) Name() string {
	return "High Cardinality Log Label"
}

func (a *HighCardinalityLogLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighCardinalityLogLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeLogLabel, model.ResourceTypeLogLabelValue}
}

func (a *HighCardinalityLogLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeLogLabel})
	if err != nil {
		return nil, err
	}
	values, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeLogLabelValue})
	if err != nil {
		return nil, err
	}

	labelByName := make(map[string]model.Resource, len(labels))
	inactiveLabelNames := make(map[string]bool)
	for _, label := range labels {
		name := strings.TrimSpace(label.Name)
		if name == "" {
			name = strings.TrimSpace(label.Metadata[model.MetadataLogLabel])
		}
		if name == "" {
			continue
		}
		if isActiveLogLabelResource(label) {
			labelByName[name] = label
			delete(inactiveLabelNames, name)
		} else if _, active := labelByName[name]; !active {
			inactiveLabelNames[name] = true
		}
	}

	valuesByLabel := make(map[string]map[string]bool)
	for _, value := range values {
		if !isActiveLogLabelResource(value) {
			continue
		}
		labelName := strings.TrimSpace(value.Metadata[model.MetadataLogLabel])
		if labelName == "" {
			labelName = logLabelNameFromValueResource(value)
		}
		if labelName == "" {
			continue
		}
		labelValue := strings.TrimSpace(value.Metadata[model.MetadataValueFingerprint])
		if labelValue == "" {
			labelValue = strings.TrimSpace(value.Metadata[model.MetadataLogLabelValue])
		}
		if labelValue == "" {
			labelValue = strings.TrimPrefix(value.Name, labelName+"=")
		}
		if labelValue == "" {
			continue
		}
		if valuesByLabel[labelName] == nil {
			valuesByLabel[labelName] = map[string]bool{}
		}
		valuesByLabel[labelName][labelValue] = true
	}

	threshold := intConfig(analysis.Config, logLabelValueCountThresholdConfigID, defaultLogLabelValueCountThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for labelName, valueSet := range valuesByLabel {
		labelResource, labelExists := labelByName[labelName]
		if inactiveLabelNames[labelName] {
			continue
		}
		count := logLabelValueCount(labelResource, len(valueSet))
		if count <= threshold {
			continue
		}
		if !labelExists {
			labelResource = model.Resource{
				ID:   model.StableID("resource", "loki", string(model.ResourceTypeLogLabel), "label:"+labelName),
				Type: model.ResourceTypeLogLabel,
				Name: labelName,
			}
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), labelResource.ID, strconv.Itoa(count)),
			Type:     "HighCardinalityLogLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   labelResource.ID,
				Type: labelResource.Type,
				Name: labelResource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("log label %q has %d discovered values, threshold is %d", labelName, count, threshold),
			},
			Recommendation: "检查 Loki 标签设计，避免把 user_id、request_id、trace_id、pod uid、path 等高基数字段放入 labels；高变化维度应保留在日志内容或结构化字段中。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"label":       labelName,
				"value_count": strconv.Itoa(count),
				"threshold":   strconv.Itoa(threshold),
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

func isActiveLogLabelResource(resource model.Resource) bool {
	return resource.Status == model.ResourceStatusActive &&
		(resource.Type == model.ResourceTypeLogLabel || resource.Type == model.ResourceTypeLogLabelValue)
}

func logLabelValueCount(label model.Resource, fallback int) int {
	raw := strings.TrimSpace(label.Metadata[model.MetadataLogLabelValueCount])
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < fallback {
		return fallback
	}
	return parsed
}

func logLabelNameFromValueResource(resource model.Resource) string {
	name := strings.TrimSpace(resource.Name)
	if index := strings.Index(name, "="); index > 0 {
		return strings.TrimSpace(name[:index])
	}
	uid := strings.TrimSpace(resource.UID)
	const prefix = "label:"
	if !strings.HasPrefix(uid, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(uid, prefix)
	index := strings.Index(rest, ":value:")
	if index <= 0 {
		return ""
	}
	return strings.TrimSpace(rest[:index])
}
