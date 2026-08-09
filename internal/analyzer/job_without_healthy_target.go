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
	JobWithoutHealthyTargetAnalyzerID = "builtin.job_without_healthy_target"
	defaultJobTargetSamples           = 8
)

type JobWithoutHealthyTargetAnalyzer struct{}

func NewJobWithoutHealthyTargetAnalyzer() *JobWithoutHealthyTargetAnalyzer {
	return &JobWithoutHealthyTargetAnalyzer{}
}

func (a *JobWithoutHealthyTargetAnalyzer) ID() string {
	return JobWithoutHealthyTargetAnalyzerID
}

func (a *JobWithoutHealthyTargetAnalyzer) Name() string {
	return "Job Without Healthy Target"
}

func (a *JobWithoutHealthyTargetAnalyzer) Version() string {
	return "0.1.0"
}

func (a *JobWithoutHealthyTargetAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeJob, model.ResourceTypeTarget}
}

func (a *JobWithoutHealthyTargetAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	jobs, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeJob})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, job := range jobs {
		if !isActivePrometheusCompatibleResource(job) {
			continue
		}
		targets := scrapeTargetsForJob(job, analysis)
		if len(targets) == 0 || healthyScrapeTargetCount(targets) > 0 {
			continue
		}

		targetNames := sampledConsumerNames(targets, defaultJobTargetSamples)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), job.ID),
			Type:     "JobWithoutHealthyTarget",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   job.ID,
				Type: job.Type,
				Name: job.Name,
			},
			Evidence: []string{
				fmt.Sprintf("scrape job %q has 0 healthy targets out of %d eligible targets", job.Name, len(targets)),
				fmt.Sprintf("unhealthy targets: %s", strings.Join(targetNames, ", ")),
			},
			Recommendation: "检查该 scrape job 的服务发现、网络连通性、认证配置和 exporter 状态；整个 job 无健康目标会造成对应指标持续断流。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"source_system":   job.Source.System,
				"target_count":    strconv.Itoa(len(targets)),
				"healthy_targets": "0",
				"targets":         strings.Join(targetNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Metadata["source_system"] != findings[j].Metadata["source_system"] {
			return findings[i].Metadata["source_system"] < findings[j].Metadata["source_system"]
		}
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func isActivePrometheusCompatibleResource(resource model.Resource) bool {
	return resource.Status == model.ResourceStatusActive && isPrometheusCompatibleSource(resource.Source.System)
}

func isPrometheusCompatibleSource(system string) bool {
	switch system {
	case "prometheus", "thanos", "victoriametrics", "mimir", "cortex":
		return true
	default:
		return false
	}
}

func scrapeTargetsForJob(job model.Resource, analysis Context) []model.Resource {
	targets := make([]model.Resource, 0)
	seen := make(map[string]bool)
	for _, relationship := range analysis.Graph.Incoming(job.ID) {
		if relationship.Type != model.RelationshipBelongsTo || seen[relationship.FromID] {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || target.Type != model.ResourceTypeTarget || target.Source.System != job.Source.System || target.Source.Instance != job.Source.Instance {
			continue
		}
		if target.Status == model.ResourceStatusDeprecated || target.Status == model.ResourceStatusDeleted {
			continue
		}
		seen[target.ID] = true
		targets = append(targets, target)
	}
	sortResourcesByTypeAndName(targets)
	return targets
}

func healthyScrapeTargetCount(targets []model.Resource) int {
	count := 0
	for _, target := range targets {
		if isHealthyScrapeTarget(target) {
			count++
		}
	}
	return count
}

func isHealthyScrapeTarget(target model.Resource) bool {
	if target.Status != model.ResourceStatusActive || strings.TrimSpace(target.Metadata[model.MetadataLastError]) != "" {
		return false
	}
	health := strings.TrimSpace(target.Metadata[model.MetadataHealth])
	return health == "" || strings.EqualFold(health, "up")
}
