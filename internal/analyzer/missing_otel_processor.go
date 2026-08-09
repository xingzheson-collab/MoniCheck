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

const MissingOTelProcessorAnalyzerID = "builtin.missing_otel_processor"

var defaultRequiredOTelProcessors = []string{"batch", "memory_limiter"}

type MissingOTelProcessorAnalyzer struct{}

func NewMissingOTelProcessorAnalyzer() *MissingOTelProcessorAnalyzer {
	return &MissingOTelProcessorAnalyzer{}
}

func (a *MissingOTelProcessorAnalyzer) ID() string {
	return MissingOTelProcessorAnalyzerID
}

func (a *MissingOTelProcessorAnalyzer) Name() string {
	return "Missing OpenTelemetry Collector Processor"
}

func (a *MissingOTelProcessorAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingOTelProcessorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePipeline}
}

func (a *MissingOTelProcessorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	pipelines, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePipeline})
	if err != nil {
		return nil, err
	}
	required := requiredOTelProcessors(analysis.Config)
	if len(required) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, pipeline := range pipelines {
		if !isActiveOTelPipeline(pipeline) {
			continue
		}
		missing := missingRequiredOTelProcessors(pipeline, required)
		if len(missing) == 0 {
			continue
		}
		signal := strings.TrimSpace(pipeline.Metadata[model.MetadataPipelineSignal])
		if signal == "" {
			signal = "unknown"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), pipeline.ID, strings.Join(missing, ",")),
			Type:     "MissingOTelProcessor",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   pipeline.ID,
				Type: pipeline.Type,
				Name: pipeline.Name,
			},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector %s pipeline %q is missing required processor(s): %s", signal, pipeline.Name, strings.Join(missing, ", ")),
			},
			Recommendation: "为 OpenTelemetry Collector pipeline 补充 batch、memory_limiter 等关键 processors；batch 提升导出效率，memory_limiter 降低内存压力下的失稳风险。可通过 required_otel_processors 调整本地要求。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"signal":      signal,
				"missing":     strings.Join(missing, ","),
				"required":    strings.Join(required, ","),
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

func requiredOTelProcessors(config map[string]any) []string {
	values := stringSliceConfig(config, "required_otel_processors", defaultRequiredOTelProcessors)
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeOTelProcessorName(value)
		if normalized != "" {
			result = append(result, normalized)
		}
	}
	return result
}

func missingRequiredOTelProcessors(pipeline model.Resource, required []string) []string {
	present := map[string]bool{}
	for _, processor := range strings.Split(pipeline.Metadata[model.MetadataPipelineProcessors], ",") {
		normalized := normalizeOTelProcessorName(processor)
		if normalized != "" {
			present[normalized] = true
		}
	}
	missing := make([]string, 0, len(required))
	for _, processor := range required {
		if !present[processor] {
			missing = append(missing, processor)
		}
	}
	return missing
}

func normalizeOTelProcessorName(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.TrimSpace(value))
}
