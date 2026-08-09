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

const RiskyLogLabelAnalyzerID = "builtin.risky_log_label"

var defaultRiskyLogLabelNames = []string{
	"user_id",
	"userid",
	"user",
	"uid",
	"request_id",
	"requestid",
	"req_id",
	"trace_id",
	"traceid",
	"span_id",
	"spanid",
	"session_id",
	"sessionid",
	"pod_uid",
	"container_id",
	"client_ip",
	"remote_addr",
	"path",
	"url",
}

type RiskyLogLabelAnalyzer struct{}

func NewRiskyLogLabelAnalyzer() *RiskyLogLabelAnalyzer {
	return &RiskyLogLabelAnalyzer{}
}

func (a *RiskyLogLabelAnalyzer) ID() string {
	return RiskyLogLabelAnalyzerID
}

func (a *RiskyLogLabelAnalyzer) Name() string {
	return "Risky Log Label"
}

func (a *RiskyLogLabelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *RiskyLogLabelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeLogLabel}
}

func (a *RiskyLogLabelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	labels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeLogLabel})
	if err != nil {
		return nil, err
	}

	riskyNames := riskyLogLabelNameSet(analysis.Config)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, label := range labels {
		if !isActiveLogLabelResource(label) {
			continue
		}
		name := strings.TrimSpace(label.Name)
		if name == "" {
			name = strings.TrimSpace(label.Metadata["label"])
		}
		normalized := normalizeLogLabelName(name)
		if normalized == "" || !riskyNames[normalized] {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), label.ID, normalized),
			Type:     "RiskyLogLabel",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   label.ID,
				Type: label.Type,
				Name: label.Name,
			},
			Evidence: []string{
				fmt.Sprintf("Loki label %q is commonly high-cardinality or user-specific", name),
			},
			Recommendation: "避免将 user/request/trace/session/path 等高变化维度作为 Loki labels；优先保留在日志内容、结构化字段或 trace 关联字段中。",
			Metadata: map[string]string{
				"analyzer_id":      a.ID(),
				"label":            name,
				"normalized_label": normalized,
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

func riskyLogLabelNameSet(config map[string]any) map[string]bool {
	values := stringSliceConfig(config, "risky_log_label_names", defaultRiskyLogLabelNames)
	result := make(map[string]bool, len(values))
	for _, value := range values {
		normalized := normalizeLogLabelName(value)
		if normalized != "" {
			result[normalized] = true
		}
	}
	return result
}

func normalizeLogLabelName(value string) string {
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(strings.ToLower(strings.TrimSpace(value)))
}
