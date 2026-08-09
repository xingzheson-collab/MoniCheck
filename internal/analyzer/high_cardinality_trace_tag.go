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
	HighCardinalityTraceTagAnalyzerID   = "builtin.high_cardinality_trace_tag"
	defaultTraceTagValueCountThreshold  = 100
	traceTagValueCountThresholdConfigID = "trace_tag_value_threshold"
)

type HighCardinalityTraceTagAnalyzer struct{}

func NewHighCardinalityTraceTagAnalyzer() *HighCardinalityTraceTagAnalyzer {
	return &HighCardinalityTraceTagAnalyzer{}
}

func (a *HighCardinalityTraceTagAnalyzer) ID() string {
	return HighCardinalityTraceTagAnalyzerID
}

func (a *HighCardinalityTraceTagAnalyzer) Name() string {
	return "High Cardinality Trace Tag"
}

func (a *HighCardinalityTraceTagAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighCardinalityTraceTagAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTraceTag, model.ResourceTypeTraceTagValue}
}

func (a *HighCardinalityTraceTagAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	tags, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTraceTag})
	if err != nil {
		return nil, err
	}
	values, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTraceTagValue})
	if err != nil {
		return nil, err
	}

	tagByName := make(map[string]model.Resource, len(tags))
	inactiveTagNames := make(map[string]bool)
	for _, tag := range tags {
		name := strings.TrimSpace(tag.Name)
		if name == "" {
			name = strings.TrimSpace(tag.Metadata[model.MetadataTraceTag])
		}
		if name == "" {
			continue
		}
		if isActiveTraceTagResource(tag) {
			tagByName[name] = tag
			delete(inactiveTagNames, name)
		} else if _, active := tagByName[name]; !active {
			inactiveTagNames[name] = true
		}
	}

	valuesByTag := make(map[string]map[string]bool)
	for _, value := range values {
		if !isActiveTraceTagResource(value) {
			continue
		}
		tagName := strings.TrimSpace(value.Metadata[model.MetadataTraceTag])
		if tagName == "" {
			tagName = traceTagNameFromValueResource(value)
		}
		if tagName == "" {
			continue
		}
		tagValue := strings.TrimSpace(value.Metadata[model.MetadataValueFingerprint])
		if tagValue == "" {
			tagValue = strings.TrimSpace(value.Metadata[model.MetadataTraceTagValue])
		}
		if tagValue == "" {
			tagValue = strings.TrimPrefix(value.Name, tagName+"=")
		}
		if tagValue == "" {
			continue
		}
		if valuesByTag[tagName] == nil {
			valuesByTag[tagName] = map[string]bool{}
		}
		valuesByTag[tagName][tagValue] = true
	}

	threshold := intConfig(analysis.Config, traceTagValueCountThresholdConfigID, defaultTraceTagValueCountThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for tagName, valueSet := range valuesByTag {
		tagResource, tagExists := tagByName[tagName]
		if inactiveTagNames[tagName] {
			continue
		}
		count := traceTagValueCount(tagResource, len(valueSet))
		if count <= threshold {
			continue
		}
		if !tagExists {
			tagResource = model.Resource{
				ID:   model.StableID("resource", "tempo", string(model.ResourceTypeTraceTag), "tag:"+tagName),
				Type: model.ResourceTypeTraceTag,
				Name: tagName,
			}
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), tagResource.ID, strconv.Itoa(count)),
			Type:     "HighCardinalityTraceTag",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   tagResource.ID,
				Type: tagResource.Type,
				Name: tagResource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("trace tag %q has %d discovered values, threshold is %d", tagName, count, threshold),
			},
			Recommendation: "检查 Tempo tag 设计，避免把 user_id、request_id、session_id、path 等高变化维度作为高频搜索标签；高变化属性应谨慎索引或转为更稳定的服务/状态维度。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"trace_tag":   tagName,
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

func isActiveTraceTagResource(resource model.Resource) bool {
	return resource.Status == model.ResourceStatusActive &&
		(resource.Type == model.ResourceTypeTraceTag || resource.Type == model.ResourceTypeTraceTagValue)
}

func traceTagValueCount(tag model.Resource, fallback int) int {
	raw := strings.TrimSpace(tag.Metadata[model.MetadataTraceTagValueCount])
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < fallback {
		return fallback
	}
	return parsed
}

func traceTagNameFromValueResource(resource model.Resource) string {
	name := strings.TrimSpace(resource.Name)
	if index := strings.Index(name, "="); index > 0 {
		return strings.TrimSpace(name[:index])
	}
	uid := strings.TrimSpace(resource.UID)
	const prefix = "tag:"
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
