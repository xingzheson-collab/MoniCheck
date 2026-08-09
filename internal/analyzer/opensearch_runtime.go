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
	OpenSearchClusterRedAnalyzerID          = "builtin.opensearch_cluster_red"
	OpenSearchClusterYellowAnalyzerID       = "builtin.opensearch_cluster_yellow"
	OpenSearchPendingTasksAnalyzerID        = "builtin.opensearch_pending_tasks"
	OpenSearchHighShardDensityAnalyzerID    = "builtin.opensearch_high_shard_density"
	OpenSearchNoDataNodesAnalyzerID         = "builtin.opensearch_no_data_nodes"
	OpenSearchNodeStatsIncompleteID         = "builtin.opensearch_node_stats_incomplete"
	OpenSearchHighDiskUsageAnalyzerID       = "builtin.opensearch_high_disk_usage"
	OpenSearchHighHeapUsageAnalyzerID       = "builtin.opensearch_high_heap_usage"
	OpenSearchHighFDUsageAnalyzerID         = "builtin.opensearch_high_file_descriptor_usage"
	ElasticsearchClusterRedAnalyzerID       = "builtin.elasticsearch_cluster_red"
	ElasticsearchClusterYellowAnalyzerID    = "builtin.elasticsearch_cluster_yellow"
	ElasticsearchPendingTasksAnalyzerID     = "builtin.elasticsearch_pending_tasks"
	ElasticsearchHighShardDensityAnalyzerID = "builtin.elasticsearch_high_shard_density"
	ElasticsearchNoDataNodesAnalyzerID      = "builtin.elasticsearch_no_data_nodes"
	ElasticsearchNodeStatsIncompleteID      = "builtin.elasticsearch_node_stats_incomplete"
	ElasticsearchHighDiskUsageAnalyzerID    = "builtin.elasticsearch_high_disk_usage"
	ElasticsearchHighHeapUsageAnalyzerID    = "builtin.elasticsearch_high_heap_usage"
	ElasticsearchHighFDUsageAnalyzerID      = "builtin.elasticsearch_high_file_descriptor_usage"
)

type OpenSearchRuntimeAnalyzer struct {
	id           string
	name         string
	kind         string
	system       string
	platform     string
	configPrefix string
}

func NewOpenSearchClusterRedAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchClusterRedAnalyzerID, "cluster_red", "opensearch", "OpenSearch")
}

func NewOpenSearchClusterYellowAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchClusterYellowAnalyzerID, "cluster_yellow", "opensearch", "OpenSearch")
}

func NewOpenSearchPendingTasksAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchPendingTasksAnalyzerID, "pending_tasks", "opensearch", "OpenSearch")
}

func NewOpenSearchHighShardDensityAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchHighShardDensityAnalyzerID, "high_shard_density", "opensearch", "OpenSearch")
}

func NewOpenSearchNoDataNodesAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchNoDataNodesAnalyzerID, "no_data_nodes", "opensearch", "OpenSearch")
}

func NewOpenSearchNodeStatsIncompleteAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchNodeStatsIncompleteID, "node_stats_incomplete", "opensearch", "OpenSearch")
}

func NewOpenSearchHighDiskUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchHighDiskUsageAnalyzerID, "high_disk_usage", "opensearch", "OpenSearch")
}

func NewOpenSearchHighHeapUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchHighHeapUsageAnalyzerID, "high_heap_usage", "opensearch", "OpenSearch")
}

func NewOpenSearchHighFDUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(OpenSearchHighFDUsageAnalyzerID, "high_fd_usage", "opensearch", "OpenSearch")
}

func NewElasticsearchClusterRedAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchClusterRedAnalyzerID, "cluster_red", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchClusterYellowAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchClusterYellowAnalyzerID, "cluster_yellow", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchPendingTasksAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchPendingTasksAnalyzerID, "pending_tasks", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchHighShardDensityAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchHighShardDensityAnalyzerID, "high_shard_density", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchNoDataNodesAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchNoDataNodesAnalyzerID, "no_data_nodes", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchNodeStatsIncompleteAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchNodeStatsIncompleteID, "node_stats_incomplete", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchHighDiskUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchHighDiskUsageAnalyzerID, "high_disk_usage", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchHighHeapUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchHighHeapUsageAnalyzerID, "high_heap_usage", "elasticsearch", "Elasticsearch")
}

func NewElasticsearchHighFDUsageAnalyzer() *OpenSearchRuntimeAnalyzer {
	return newSearchRuntimeAnalyzer(ElasticsearchHighFDUsageAnalyzerID, "high_fd_usage", "elasticsearch", "Elasticsearch")
}

func newSearchRuntimeAnalyzer(id, kind, system, platform string) *OpenSearchRuntimeAnalyzer {
	names := map[string]string{
		"cluster_red":           "Cluster Red",
		"cluster_yellow":        "Cluster Yellow",
		"pending_tasks":         "Pending Tasks",
		"high_shard_density":    "High Shard Density",
		"no_data_nodes":         "Without Data Nodes",
		"node_stats_incomplete": "Node Stats Incomplete",
		"high_disk_usage":       "High Disk Usage",
		"high_heap_usage":       "High JVM Heap Usage",
		"high_fd_usage":         "High File Descriptor Usage",
	}
	return &OpenSearchRuntimeAnalyzer{
		id:           id,
		name:         platform + " " + names[kind],
		kind:         kind,
		system:       system,
		platform:     platform,
		configPrefix: system,
	}
}

func (a *OpenSearchRuntimeAnalyzer) ID() string      { return a.id }
func (a *OpenSearchRuntimeAnalyzer) Name() string    { return a.name }
func (a *OpenSearchRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *OpenSearchRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *OpenSearchRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	instances, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, instance := range instances {
		if instance.Status != model.ResourceStatusActive ||
			instance.Source.System != a.system ||
			instance.Metadata[a.metadataKey(model.MetadataOpenSearchHealthAvailable)] != "true" {
			continue
		}
		if finding, ok := a.finding(instance, analysis.Config, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *OpenSearchRuntimeAnalyzer) finding(instance model.Resource, config map[string]any, now time.Time) (model.Finding, bool) {
	status := strings.ToLower(strings.TrimSpace(instance.Metadata[a.metadataKey(model.MetadataOpenSearchClusterStatus)]))
	pendingTasks := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchPendingTasks))
	maxWaitMillis := openSearchMetadataInt64(instance, a.metadataKey(model.MetadataOpenSearchMaxTaskWaitMillis))
	shardsPerDataNode := openSearchMetadataFloat(instance, a.metadataKey(model.MetadataOpenSearchShardsPerDataNode))
	dataNodeCount := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchDataNodeCount))
	nodeStatsAvailable := instance.Metadata[a.metadataKey(model.MetadataOpenSearchNodeStatsAvailable)] == "true"
	nodeStatsTotal := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchNodeStatsTotal))
	nodeStatsSuccessful := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchNodeStatsSuccessful))
	nodeStatsFailed := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchNodeStatsFailed))
	maxDiskUsedPercent := openSearchMetadataFloat(instance, a.metadataKey(model.MetadataOpenSearchMaxDiskUsedPercent))
	maxHeapUsedPercent := openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchMaxHeapUsedPercent))
	maxFDUsedPercent := openSearchMetadataFloat(instance, a.metadataKey(model.MetadataOpenSearchMaxFDUsedPercent))
	pendingThreshold := intConfig(config, a.configPrefix+"_pending_task_threshold", 100)
	waitThreshold := durationConfig(config, a.configPrefix+"_task_wait_threshold", 30*time.Second)
	shardThreshold := floatConfig(config, a.configPrefix+"_shards_per_data_node_threshold", 1000)
	diskThreshold := floatConfig(config, a.configPrefix+"_disk_usage_threshold", 85)
	diskCriticalThreshold := floatConfig(config, a.configPrefix+"_disk_usage_critical_threshold", 95)
	if diskCriticalThreshold < diskThreshold {
		diskCriticalThreshold = diskThreshold
	}
	heapThreshold := intConfig(config, a.configPrefix+"_heap_usage_threshold", 85)
	fdThreshold := floatConfig(config, a.configPrefix+"_file_descriptor_usage_threshold", 80)

	var findingType, evidence, recommendation string
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	switch a.kind {
	case "cluster_red":
		if status != "red" {
			return model.Finding{}, false
		}
		findingType = a.platform + "ClusterRed"
		severity = model.SeverityCritical
		evidence = fmt.Sprintf("%s cluster health is red with %d unassigned shard(s)", a.platform, openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchUnassignedShards)))
		recommendation = "立即定位未分配的主分片、不可用数据节点和磁盘水位；恢复主分片分配并确认集群健康回到 green。"
	case "cluster_yellow":
		if status != "yellow" {
			return model.Finding{}, false
		}
		findingType = a.platform + "ClusterYellow"
		evidence = fmt.Sprintf("%s cluster health is yellow with %d unassigned shard(s)", a.platform, openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchUnassignedShards)))
		recommendation = "检查副本分片未分配原因、节点数量和分配过滤条件；恢复副本冗余并确认集群健康回到 green。"
	case "pending_tasks":
		if pendingTasks < pendingThreshold && time.Duration(maxWaitMillis)*time.Millisecond < waitThreshold {
			return model.Finding{}, false
		}
		findingType = a.platform + "PendingTasks"
		evidence = fmt.Sprintf("%s has %d pending cluster task(s); the longest queued task has waited %d ms", a.platform, pendingTasks, maxWaitMillis)
		recommendation = "检查 cluster manager 节点负载、集群状态更新和分片分配活动；减少积压来源并持续观察任务队列等待时间。"
	case "high_shard_density":
		if shardsPerDataNode <= shardThreshold {
			return model.Finding{}, false
		}
		findingType = a.platform + "HighShardDensity"
		category = model.FindingCategoryCost
		evidence = fmt.Sprintf("%s has %.2f active shards per data node, above the configured %.2f threshold", a.platform, shardsPerDataNode, shardThreshold)
		recommendation = "合并过小索引、调整 rollover 与分片数量，并按容量规划增加数据节点，降低单节点分片管理和堆内存开销。"
	case "no_data_nodes":
		if dataNodeCount > 0 {
			return model.Finding{}, false
		}
		findingType = a.platform + "NoDataNodes"
		severity = model.SeverityCritical
		evidence = a.platform + " cluster health reports zero data nodes"
		recommendation = "立即恢复至少一个可用数据节点并检查节点角色、发现配置和调度状态；确认主分片恢复后再接受写入流量。"
	case "node_stats_incomplete":
		if !nodeStatsAvailable || (nodeStatsFailed == 0 && (nodeStatsTotal == 0 || nodeStatsSuccessful >= nodeStatsTotal)) {
			return model.Finding{}, false
		}
		findingType = a.platform + "NodeStatsIncomplete"
		evidence = fmt.Sprintf("%s node stats covered %d of %d node(s) with %d failed response(s)", a.platform, nodeStatsSuccessful, nodeStatsTotal, nodeStatsFailed)
		recommendation = "检查未返回统计的节点状态、权限和网络连通性；恢复完整 nodes stats 覆盖后再依赖容量结论。"
	case "high_disk_usage":
		if !nodeStatsAvailable || openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchDiskStatsNodeCount)) == 0 || maxDiskUsedPercent < diskThreshold {
			return model.Finding{}, false
		}
		findingType = a.platform + "HighDiskUsage"
		if maxDiskUsedPercent >= diskCriticalThreshold {
			severity = model.SeverityCritical
		}
		evidence = fmt.Sprintf("%s maximum node disk usage is %.2f%%; minimum available capacity is %d bytes", a.platform, maxDiskUsedPercent, openSearchMetadataInt64(instance, a.metadataKey(model.MetadataOpenSearchMinDiskAvailable)))
		recommendation = "清理或迁移冷数据、调整 ISM/保留策略并扩容数据节点；同时确认磁盘水位分配策略能够阻止容量耗尽。"
	case "high_heap_usage":
		if !nodeStatsAvailable || openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchHeapStatsNodeCount)) == 0 || maxHeapUsedPercent < heapThreshold {
			return model.Finding{}, false
		}
		findingType = a.platform + "HighHeapUsage"
		evidence = fmt.Sprintf("%s maximum node JVM heap usage is %d%%, at or above the configured %d%% threshold", a.platform, maxHeapUsedPercent, heapThreshold)
		recommendation = "检查分片数量、聚合查询和 fielddata/circuit breaker 压力；降低堆负载或按当前搜索平台的运行建议扩容节点。"
	case "high_fd_usage":
		if !nodeStatsAvailable || openSearchMetadataInt(instance, a.metadataKey(model.MetadataOpenSearchFDStatsNodeCount)) == 0 || maxFDUsedPercent < fdThreshold {
			return model.Finding{}, false
		}
		findingType = a.platform + "HighFileDescriptorUsage"
		evidence = fmt.Sprintf("%s maximum node file descriptor usage is %.2f%%, at or above the configured %.2f%% threshold", a.platform, maxFDUsedPercent, fdThreshold)
		recommendation = "检查分片和连接数量、泄漏的客户端连接及操作系统 nofile 限制；释放异常占用并提高经过容量验证的限制。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, instance.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       category,
		Resource:       model.ResourceRef{ID: instance.ID, Type: instance.Type, Name: instance.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata: map[string]string{
			"analyzer_id":           a.id,
			"cluster_status":        status,
			"pending_task_count":    strconv.Itoa(pendingTasks),
			"max_task_wait_millis":  strconv.FormatInt(maxWaitMillis, 10),
			"shards_per_data_node":  strconv.FormatFloat(shardsPerDataNode, 'f', 2, 64),
			"data_node_count":       strconv.Itoa(dataNodeCount),
			"node_stats_total":      strconv.Itoa(nodeStatsTotal),
			"node_stats_successful": strconv.Itoa(nodeStatsSuccessful),
			"node_stats_failed":     strconv.Itoa(nodeStatsFailed),
			"max_disk_used_percent": strconv.FormatFloat(maxDiskUsedPercent, 'f', 2, 64),
			"max_heap_used_percent": strconv.Itoa(maxHeapUsedPercent),
			"max_fd_used_percent":   strconv.FormatFloat(maxFDUsedPercent, 'f', 2, 64),
		},
		Status:    model.FindingStatusOpen,
		CreatedAt: now,
		UpdatedAt: now,
	}, true
}

func (a *OpenSearchRuntimeAnalyzer) metadataKey(key string) string {
	if a.system == "elasticsearch" {
		return strings.Replace(key, "opensearch_", "elasticsearch_", 1)
	}
	return key
}

func openSearchMetadataInt(resource model.Resource, key string) int {
	value, _ := strconv.Atoi(resource.Metadata[key])
	return max(0, value)
}

func openSearchMetadataInt64(resource model.Resource, key string) int64 {
	value, _ := strconv.ParseInt(resource.Metadata[key], 10, 64)
	return max(0, value)
}

func openSearchMetadataFloat(resource model.Resource, key string) float64 {
	value, _ := strconv.ParseFloat(resource.Metadata[key], 64)
	return max(0, value)
}
