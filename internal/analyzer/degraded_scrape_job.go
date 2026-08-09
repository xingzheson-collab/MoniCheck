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
	DegradedScrapeJobAnalyzerID           = "builtin.degraded_scrape_job"
	defaultScrapeJobHealthyRatioThreshold = 0.8
)

type DegradedScrapeJobAnalyzer struct{}

func NewDegradedScrapeJobAnalyzer() *DegradedScrapeJobAnalyzer {
	return &DegradedScrapeJobAnalyzer{}
}

func (a *DegradedScrapeJobAnalyzer) ID() string {
	return DegradedScrapeJobAnalyzerID
}

func (a *DegradedScrapeJobAnalyzer) Name() string {
	return "Degraded Scrape Job"
}

func (a *DegradedScrapeJobAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DegradedScrapeJobAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeJob, model.ResourceTypeTarget}
}

func (a *DegradedScrapeJobAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	jobs, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeJob})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := floatConfig(analysis.Config, "scrape_job_healthy_ratio_threshold", defaultScrapeJobHealthyRatioThreshold)
	if threshold <= 0 || threshold > 1 {
		threshold = defaultScrapeJobHealthyRatioThreshold
	}
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_degraded_scrape_jobs", nil))
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, job := range jobs {
		if !isActivePrometheusCompatibleResource(job) || allowedResource(job, allowed) {
			continue
		}
		targets := scrapeTargetsForJob(job, analysis)
		healthyCount := healthyScrapeTargetCount(targets)
		if len(targets) == 0 || healthyCount == 0 {
			continue
		}
		healthyRatio := float64(healthyCount) / float64(len(targets))
		if healthyRatio >= threshold {
			continue
		}

		unhealthyTargets := unhealthyScrapeTargets(targets)
		unhealthyNames := sampledConsumerNames(unhealthyTargets, defaultJobTargetSamples)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), job.ID),
			Type:     "DegradedScrapeJob",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   job.ID,
				Type: job.Type,
				Name: job.Name,
			},
			Evidence: []string{
				fmt.Sprintf("scrape job %q has %d healthy targets out of %d (ratio %.2f, threshold %.2f)", job.Name, healthyCount, len(targets), healthyRatio, threshold),
				fmt.Sprintf("unhealthy targets: %s", strings.Join(unhealthyNames, ", ")),
			},
			Recommendation: "检查异常 Target 的 exporter、网络、认证和服务发现状态；部分实例停止采集会导致聚合指标偏低、分位数失真并削弱告警覆盖。",
			Metadata: map[string]string{
				"analyzer_id":       a.ID(),
				"source_system":     job.Source.System,
				"target_count":      strconv.Itoa(len(targets)),
				"healthy_targets":   strconv.Itoa(healthyCount),
				"unhealthy_targets": strconv.Itoa(len(unhealthyTargets)),
				"healthy_ratio":     fmt.Sprintf("%.4f", healthyRatio),
				"threshold":         fmt.Sprintf("%.4f", threshold),
				"targets":           strings.Join(unhealthyNames, ","),
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

func unhealthyScrapeTargets(targets []model.Resource) []model.Resource {
	unhealthy := make([]model.Resource, 0)
	for _, target := range targets {
		if !isHealthyScrapeTarget(target) {
			unhealthy = append(unhealthy, target)
		}
	}
	return unhealthy
}
