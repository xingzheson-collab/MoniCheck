package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	AlertmanagerClusterNotReadyAnalyzerID  = "builtin.alertmanager_cluster_not_ready"
	AlertmanagerSingletonClusterAnalyzerID = "builtin.alertmanager_singleton_cluster"
)

type AlertmanagerRuntimeAnalyzer struct {
	id   string
	name string
}

func NewAlertmanagerClusterNotReadyAnalyzer() *AlertmanagerRuntimeAnalyzer {
	return &AlertmanagerRuntimeAnalyzer{id: AlertmanagerClusterNotReadyAnalyzerID, name: "Alertmanager Cluster Not Ready"}
}

func NewAlertmanagerSingletonClusterAnalyzer() *AlertmanagerRuntimeAnalyzer {
	return &AlertmanagerRuntimeAnalyzer{id: AlertmanagerSingletonClusterAnalyzerID, name: "Alertmanager Singleton Cluster"}
}

func (a *AlertmanagerRuntimeAnalyzer) ID() string      { return a.id }
func (a *AlertmanagerRuntimeAnalyzer) Name() string    { return a.name }
func (a *AlertmanagerRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *AlertmanagerRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *AlertmanagerRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	instances, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, instance := range instances {
		if instance.Status != model.ResourceStatusActive ||
			instance.Source.System != "alertmanager" ||
			instance.Metadata[model.MetadataAlertmanagerRuntime] != "true" {
			continue
		}
		if finding, ok := a.finding(instance, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *AlertmanagerRuntimeAnalyzer) finding(instance model.Resource, now time.Time) (model.Finding, bool) {
	status := strings.ToLower(strings.TrimSpace(instance.Metadata[model.MetadataAlertmanagerClusterStatus]))
	peerCount, _ := strconv.Atoi(instance.Metadata[model.MetadataAlertmanagerClusterPeerCount])
	var findingType string
	var evidence string
	var recommendation string

	switch a.id {
	case AlertmanagerClusterNotReadyAnalyzerID:
		if status == "ready" || status == "disabled" || status == "" {
			return model.Finding{}, false
		}
		findingType = "AlertmanagerClusterNotReady"
		evidence = fmt.Sprintf("Alertmanager cluster status is %q with %d visible peer(s)", status, peerCount)
		recommendation = "检查 gossip 端口的 TCP/UDP 连通性、peer 地址和启动日志；等待集群完成 settling 后重新同步，并确认各实例看到一致的成员数。"
	case AlertmanagerSingletonClusterAnalyzerID:
		if status != "ready" || peerCount >= 2 {
			return model.Finding{}, false
		}
		findingType = "AlertmanagerSingletonCluster"
		evidence = fmt.Sprintf("Alertmanager HA mode is ready but exposes only %d cluster peer", peerCount)
		recommendation = "为生产告警链路部署至少两个可相互发现的 Alertmanager 实例，并让 Prometheus 直接向所有实例发送告警，避免单实例故障中断通知。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, instance.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       model.FindingCategoryReliability,
		Resource:       model.ResourceRef{ID: instance.ID, Type: instance.Type, Name: instance.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata: map[string]string{
			"analyzer_id":    a.id,
			"cluster_status": status,
			"peer_count":     strconv.Itoa(peerCount),
		},
		Status:    model.FindingStatusOpen,
		CreatedAt: now,
		UpdatedAt: now,
	}, true
}
