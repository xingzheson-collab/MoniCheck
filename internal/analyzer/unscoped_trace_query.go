package analyzer

import (
	"context"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

const UnscopedTraceQueryAnalyzerID = "builtin.unscoped_trace_query"

type UnscopedTraceQueryAnalyzer struct{}

func NewUnscopedTraceQueryAnalyzer() *UnscopedTraceQueryAnalyzer {
	return &UnscopedTraceQueryAnalyzer{}
}

func (a *UnscopedTraceQueryAnalyzer) ID() string {
	return UnscopedTraceQueryAnalyzerID
}

func (a *UnscopedTraceQueryAnalyzer) Name() string {
	return "Unscoped Trace Query"
}

func (a *UnscopedTraceQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnscopedTraceQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard, model.ResourceTypePanel}
}

func (a *UnscopedTraceQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := listQueryResources(ctx, analysis.Resources)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if !strings.Contains(strings.ToLower(resource.Metadata[model.MetadataQueryLanguage]), "traceql") {
			continue
		}
		query := strings.TrimSpace(resource.Metadata[model.MetadataQuery])
		if query == "" || traceQueryHasScope(query) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), resource.ID),
			Type:     "UnscopedTraceQuery",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   resource.ID,
				Type: resource.Type,
				Name: resource.Name,
			},
			Evidence: []string{
				"TraceQL query has no resource, span, or service attribute constraint",
			},
			Recommendation: "为 TraceQL 增加 resource.service.name、service.name、span.name、status 或关键业务属性过滤，避免 Tempo 大范围 trace 扫描。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func traceQueryHasScope(query string) bool {
	for _, selector := range traceSelectors(query) {
		if traceSelectorHasConstraint(selector) {
			return true
		}
	}
	return false
}

func traceSelectors(query string) []string {
	selectors := logStreamSelectors(query)
	seen := map[string]bool{}
	for _, selector := range selectors {
		seen[selector] = true
	}
	result := make([]string, 0, len(seen))
	for selector := range seen {
		result = append(result, selector)
	}
	sort.Strings(result)
	return result
}

func traceSelectorHasConstraint(selector string) bool {
	selector = strings.TrimSpace(selector)
	selector = strings.TrimPrefix(selector, "{")
	selector = strings.TrimSuffix(selector, "}")
	for _, matcher := range splitLogMatchers(selector) {
		name := traceMatcherName(matcher)
		if name != "" {
			return true
		}
	}
	return false
}

func traceMatcherName(matcher string) string {
	matcher = strings.TrimSpace(matcher)
	for _, operator := range []string{"!~", "=~", "!=", "=", ">", "<"} {
		if index := strings.Index(matcher, operator); index >= 0 {
			return strings.Trim(strings.TrimSpace(matcher[:index]), ".")
		}
	}
	return ""
}
