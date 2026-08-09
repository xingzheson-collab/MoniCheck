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

const RiskyTraceTagAnalyzerID = "builtin.risky_trace_tag"

var defaultRiskyTraceTagNames = []string{
	"user_id",
	"userid",
	"user",
	"uid",
	"enduser.id",
	"enduser_id",
	"request_id",
	"requestid",
	"req_id",
	"session_id",
	"sessionid",
	"http.target",
	"http.url",
	"url",
	"path",
	"db.statement",
	"messaging.message.id",
	"message_id",
}

type RiskyTraceTagAnalyzer struct{}

func NewRiskyTraceTagAnalyzer() *RiskyTraceTagAnalyzer {
	return &RiskyTraceTagAnalyzer{}
}

func (a *RiskyTraceTagAnalyzer) ID() string {
	return RiskyTraceTagAnalyzerID
}

func (a *RiskyTraceTagAnalyzer) Name() string {
	return "Risky Trace Tag"
}

func (a *RiskyTraceTagAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RiskyTraceTagAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTraceTag}
}

func (a *RiskyTraceTagAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	tags, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTraceTag})
	if err != nil {
		return nil, err
	}

	riskyNames := riskyTraceTagNameSet(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, tag := range tags {
		if !isActiveTraceTagResource(tag) {
			continue
		}
		name := strings.TrimSpace(tag.Name)
		if name == "" {
			name = strings.TrimSpace(tag.Metadata[model.MetadataTraceTag])
		}
		normalized := normalizeTraceTagName(name)
		if normalized == "" || !riskyNames[normalized] {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), tag.ID, normalized),
			Type:     "RiskyTraceTag",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   tag.ID,
				Type: tag.Type,
				Name: tag.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Tempo trace tag %q is commonly high-cardinality, user-specific, or payload-specific", name),
			},
			Recommendation: "避免把 user/request/session/path/url/db.statement 等高变化或载荷型字段作为 Tempo 高频搜索 tag；优先使用 service、operation、status、namespace 等稳定维度。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"trace_tag":      name,
				"normalized_tag": normalized,
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

func riskyTraceTagNameSet(config map[string]any) map[string]bool {
	values := stringSliceConfig(config, "risky_trace_tag_names", defaultRiskyTraceTagNames)
	result := make(map[string]bool, len(values))
	for _, value := range values {
		normalized := normalizeTraceTagName(value)
		if normalized != "" {
			result[normalized] = true
		}
	}
	return result
}

func normalizeTraceTagName(value string) string {
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(strings.ToLower(strings.TrimSpace(value)))
}
