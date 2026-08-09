package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
)

const (
	openSearchSystem          = "opensearch"
	elasticsearchSystem       = "elasticsearch"
	openSearchMaxResponseSize = 16 << 20
	openSearchMaxIndexRows    = 100000
)

type OpenSearchConnector struct {
	baseURL     string
	client      *http.Client
	system      string
	displayName string
}

type openSearchHealth struct {
	Status                      string  `json:"status"`
	TimedOut                    bool    `json:"timed_out"`
	NumberOfNodes               int     `json:"number_of_nodes"`
	NumberOfDataNodes           int     `json:"number_of_data_nodes"`
	DiscoveredClusterManager    *bool   `json:"discovered_cluster_manager"`
	DiscoveredMaster            *bool   `json:"discovered_master"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	ActiveShards                int     `json:"active_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	DelayedUnassignedShards     int     `json:"delayed_unassigned_shards"`
	NumberOfPendingTasks        int     `json:"number_of_pending_tasks"`
	NumberOfInFlightFetch       int     `json:"number_of_in_flight_fetch"`
	TaskMaxWaitingInQueueMillis int64   `json:"task_max_waiting_in_queue_millis"`
	ActiveShardsPercent         float64 `json:"active_shards_percent_as_number"`
}

type openSearchIndexRow struct {
	Health     string `json:"health"`
	Status     string `json:"status"`
	Documents  string `json:"docs.count"`
	StoreBytes string `json:"store.size"`
	Primary    string `json:"pri"`
	Replica    string `json:"rep"`
}

type openSearchIndexSummary struct {
	Count      int
	Green      int
	Yellow     int
	Red        int
	Open       int
	Closed     int
	Documents  int64
	StoreBytes int64
}

type openSearchNodeStats struct {
	NodesSummary struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_nodes"`
	Nodes map[string]struct {
		FS struct {
			Total struct {
				TotalBytes     int64 `json:"total_in_bytes"`
				AvailableBytes int64 `json:"available_in_bytes"`
			} `json:"total"`
		} `json:"fs"`
		JVM struct {
			Memory struct {
				HeapUsedPercent *int `json:"heap_used_percent"`
			} `json:"mem"`
		} `json:"jvm"`
		Process struct {
			OpenFileDescriptors int64 `json:"open_file_descriptors"`
			MaxFileDescriptors  int64 `json:"max_file_descriptors"`
		} `json:"process"`
	} `json:"nodes"`
}

type openSearchNodeSummary struct {
	Total                 int
	Successful            int
	Failed                int
	DiskNodeCount         int
	MaxDiskUsedPercent    float64
	MinDiskAvailableBytes int64
	HeapNodeCount         int
	MaxHeapUsedPercent    int
	FDNodeCount           int
	MaxFDUsedPercent      float64
}

func NewOpenSearchConnectorWithOptions(baseURL string, options HTTPOptions) (*OpenSearchConnector, error) {
	return newSearchClusterConnector(baseURL, openSearchSystem, "OpenSearch", options)
}

func NewElasticsearchConnectorWithOptions(baseURL string, options HTTPOptions) (*OpenSearchConnector, error) {
	return newSearchClusterConnector(baseURL, elasticsearchSystem, "Elasticsearch", options)
}

func newSearchClusterConnector(baseURL, system, displayName string, options HTTPOptions) (*OpenSearchConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid %s url %q", system, baseURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid %s url scheme %q", system, parsed.Scheme)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("invalid %s url: userinfo credentials are not allowed", system)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &OpenSearchConnector{
		baseURL:     parsed.String(),
		client:      client,
		system:      system,
		displayName: displayName,
	}, nil
}

func (c *OpenSearchConnector) ID() string   { return c.system }
func (c *OpenSearchConnector) Name() string { return c.displayName + " Connector" }

func (c *OpenSearchConnector) Sync(ctx context.Context) (Snapshot, error) {
	health, err := c.fetchHealth(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	resource := c.clusterResource(health, time.Now().UTC())
	indexSummary, indexErr := c.fetchIndexSummary(ctx)
	resource.Metadata[c.metadataKey(model.MetadataOpenSearchIndexStatsAvailable)] = strconv.FormatBool(indexErr == nil)
	if indexErr == nil {
		applyOpenSearchIndexSummary(resource.Metadata, c.system, indexSummary)
	}
	nodeSummary, nodeErr := c.fetchNodeSummary(ctx)
	resource.Metadata[c.metadataKey(model.MetadataOpenSearchNodeStatsAvailable)] = strconv.FormatBool(nodeErr == nil)
	if nodeErr == nil {
		applyOpenSearchNodeSummary(resource.Metadata, c.system, nodeSummary)
	}
	return Snapshot{
		Resources: []model.Resource{resource},
		Diagnostics: []model.Diagnostic{
			searchClusterIndexDiagnostic(c.system, c.displayName, indexErr, indexSummary.Count),
			searchClusterNodeDiagnostic(c.system, c.displayName, nodeErr, nodeSummary),
		},
		Partial: indexErr != nil || nodeErr != nil,
	}, nil
}

func (c *OpenSearchConnector) fetchHealth(ctx context.Context) (openSearchHealth, error) {
	var health openSearchHealth
	if err := c.getJSON(ctx, "/_cluster/health", &health); err != nil {
		return health, fmt.Errorf("%s cluster health: %w", c.system, err)
	}
	status := strings.ToLower(strings.TrimSpace(health.Status))
	if status != "green" && status != "yellow" && status != "red" {
		return health, fmt.Errorf("%s cluster health returned invalid status", c.system)
	}
	return health, nil
}

func (c *OpenSearchConnector) fetchIndexSummary(ctx context.Context) (openSearchIndexSummary, error) {
	path := "/_cat/indices?format=json&bytes=b&h=health,status,pri,rep,docs.count,store.size"
	var rows []openSearchIndexRow
	if err := c.getJSON(ctx, path, &rows); err != nil {
		return openSearchIndexSummary{}, err
	}
	if len(rows) > openSearchMaxIndexRows {
		return openSearchIndexSummary{}, fmt.Errorf("%s index response exceeds %d rows", c.system, openSearchMaxIndexRows)
	}
	summary := openSearchIndexSummary{Count: len(rows)}
	for _, row := range rows {
		switch strings.ToLower(strings.TrimSpace(row.Health)) {
		case "green":
			summary.Green++
		case "yellow":
			summary.Yellow++
		case "red":
			summary.Red++
		}
		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case "open":
			summary.Open++
		case "close", "closed":
			summary.Closed++
		}
		summary.Documents += nonNegativeInt64(row.Documents)
		summary.StoreBytes += nonNegativeInt64(row.StoreBytes)
	}
	return summary, nil
}

func (c *OpenSearchConnector) fetchNodeSummary(ctx context.Context) (openSearchNodeSummary, error) {
	path := "/_nodes/stats/fs,jvm,process?filter_path=_nodes.total,_nodes.successful,_nodes.failed,nodes.*.fs.total.total_in_bytes,nodes.*.fs.total.available_in_bytes,nodes.*.jvm.mem.heap_used_percent,nodes.*.process.open_file_descriptors,nodes.*.process.max_file_descriptors"
	var stats openSearchNodeStats
	if err := c.getJSON(ctx, path, &stats); err != nil {
		return openSearchNodeSummary{}, err
	}
	summary := openSearchNodeSummary{
		Total:      max(0, stats.NodesSummary.Total),
		Successful: max(0, stats.NodesSummary.Successful),
		Failed:     max(0, stats.NodesSummary.Failed),
	}
	firstDisk := true
	for _, node := range stats.Nodes {
		totalBytes := node.FS.Total.TotalBytes
		availableBytes := node.FS.Total.AvailableBytes
		if totalBytes > 0 && availableBytes >= 0 {
			summary.DiskNodeCount++
			availableBytes = min(availableBytes, totalBytes)
			usedPercent := float64(totalBytes-availableBytes) / float64(totalBytes) * 100
			summary.MaxDiskUsedPercent = max(summary.MaxDiskUsedPercent, usedPercent)
			if firstDisk || availableBytes < summary.MinDiskAvailableBytes {
				summary.MinDiskAvailableBytes = availableBytes
				firstDisk = false
			}
		}
		if node.JVM.Memory.HeapUsedPercent != nil && *node.JVM.Memory.HeapUsedPercent >= 0 {
			summary.HeapNodeCount++
			summary.MaxHeapUsedPercent = max(summary.MaxHeapUsedPercent, *node.JVM.Memory.HeapUsedPercent)
		}
		if node.Process.MaxFileDescriptors > 0 && node.Process.OpenFileDescriptors >= 0 {
			summary.FDNodeCount++
			usedPercent := float64(node.Process.OpenFileDescriptors) / float64(node.Process.MaxFileDescriptors) * 100
			summary.MaxFDUsedPercent = max(summary.MaxFDUsedPercent, usedPercent)
		}
	}
	return summary, nil
}

func (c *OpenSearchConnector) getJSON(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("endpoint returned status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, openSearchMaxResponseSize))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *OpenSearchConnector) clusterResource(health openSearchHealth, now time.Time) model.Resource {
	externalID := "cluster"
	id := model.StableID(string(model.ResourceTypeInstance), c.system, c.baseURL, externalID)
	managerDiscovered := health.DiscoveredClusterManager
	if managerDiscovered == nil {
		managerDiscovered = health.DiscoveredMaster
	}
	metadata := map[string]string{
		c.metadataKey(model.MetadataOpenSearchHealthAvailable):     "true",
		c.metadataKey(model.MetadataOpenSearchClusterStatus):       strings.ToLower(strings.TrimSpace(health.Status)),
		c.metadataKey(model.MetadataOpenSearchTimedOut):            strconv.FormatBool(health.TimedOut),
		c.metadataKey(model.MetadataOpenSearchNodeCount):           strconv.Itoa(max(0, health.NumberOfNodes)),
		c.metadataKey(model.MetadataOpenSearchDataNodeCount):       strconv.Itoa(max(0, health.NumberOfDataNodes)),
		c.metadataKey(model.MetadataOpenSearchActivePrimaryShards): strconv.Itoa(max(0, health.ActivePrimaryShards)),
		c.metadataKey(model.MetadataOpenSearchActiveShards):        strconv.Itoa(max(0, health.ActiveShards)),
		c.metadataKey(model.MetadataOpenSearchRelocatingShards):    strconv.Itoa(max(0, health.RelocatingShards)),
		c.metadataKey(model.MetadataOpenSearchInitializingShards):  strconv.Itoa(max(0, health.InitializingShards)),
		c.metadataKey(model.MetadataOpenSearchDelayedShards):       strconv.Itoa(max(0, health.DelayedUnassignedShards)),
		c.metadataKey(model.MetadataOpenSearchPendingTasks):        strconv.Itoa(max(0, health.NumberOfPendingTasks)),
		c.metadataKey(model.MetadataOpenSearchInFlightFetches):     strconv.Itoa(max(0, health.NumberOfInFlightFetch)),
		c.metadataKey(model.MetadataOpenSearchMaxTaskWaitMillis):   strconv.FormatInt(max(0, health.TaskMaxWaitingInQueueMillis), 10),
		c.metadataKey(model.MetadataOpenSearchActiveShardPercent):  strconv.FormatFloat(max(0, health.ActiveShardsPercent), 'f', -1, 64),
	}
	if health.NumberOfDataNodes > 0 {
		metadata[c.metadataKey(model.MetadataOpenSearchShardsPerDataNode)] = strconv.FormatFloat(
			float64(max(0, health.ActiveShards))/float64(health.NumberOfDataNodes),
			'f',
			2,
			64,
		)
	}
	if health.UnassignedShards >= 0 {
		metadata[c.metadataKey(model.MetadataOpenSearchUnassignedShards)] = strconv.Itoa(health.UnassignedShards)
	}
	if managerDiscovered != nil {
		metadata[c.metadataKey(model.MetadataOpenSearchManagerDiscovered)] = strconv.FormatBool(*managerDiscovered)
	}
	return model.Resource{
		ID:        id,
		UID:       id,
		Type:      model.ResourceTypeInstance,
		Name:      c.displayName + " Cluster",
		Source:    model.SourceInfo{System: c.system, Instance: c.baseURL, ExternalID: externalID},
		Metadata:  metadata,
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *OpenSearchConnector) metadataKey(key string) string {
	return searchClusterMetadataKey(c.system, key)
}

func searchClusterMetadataKey(system, key string) string {
	if system == elasticsearchSystem {
		return strings.Replace(key, "opensearch_", "elasticsearch_", 1)
	}
	return key
}

func applyOpenSearchIndexSummary(metadata map[string]string, system string, summary openSearchIndexSummary) {
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchIndexCount)] = strconv.Itoa(summary.Count)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchGreenIndexCount)] = strconv.Itoa(summary.Green)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchYellowIndexCount)] = strconv.Itoa(summary.Yellow)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchRedIndexCount)] = strconv.Itoa(summary.Red)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchOpenIndexCount)] = strconv.Itoa(summary.Open)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchClosedIndexCount)] = strconv.Itoa(summary.Closed)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchDocumentCount)] = strconv.FormatInt(summary.Documents, 10)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchStoreBytes)] = strconv.FormatInt(summary.StoreBytes, 10)
}

func applyOpenSearchNodeSummary(metadata map[string]string, system string, summary openSearchNodeSummary) {
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchNodeStatsTotal)] = strconv.Itoa(summary.Total)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchNodeStatsSuccessful)] = strconv.Itoa(summary.Successful)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchNodeStatsFailed)] = strconv.Itoa(summary.Failed)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchDiskStatsNodeCount)] = strconv.Itoa(summary.DiskNodeCount)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchMaxDiskUsedPercent)] = strconv.FormatFloat(summary.MaxDiskUsedPercent, 'f', 2, 64)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchMinDiskAvailable)] = strconv.FormatInt(summary.MinDiskAvailableBytes, 10)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchHeapStatsNodeCount)] = strconv.Itoa(summary.HeapNodeCount)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchMaxHeapUsedPercent)] = strconv.Itoa(summary.MaxHeapUsedPercent)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchFDStatsNodeCount)] = strconv.Itoa(summary.FDNodeCount)
	metadata[searchClusterMetadataKey(system, model.MetadataOpenSearchMaxFDUsedPercent)] = strconv.FormatFloat(summary.MaxFDUsedPercent, 'f', 2, 64)
}

func searchClusterIndexDiagnostic(system, displayName string, err error, resourceCount int) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := displayName + " aggregate index discovery completed"
	if err != nil {
		status = model.ExecutionStatusWarning
		message = displayName + " aggregate index endpoint is unavailable; cluster health discovery continued"
		resourceCount = 0
	}
	return model.Diagnostic{
		ID:            system + "_index_stats",
		Name:          displayName + " aggregate index stats",
		Status:        status,
		Message:       message,
		ResourceCount: resourceCount,
		Metadata: map[string]string{
			"endpoint": "/_cat/indices",
			"optional": "true",
			"system":   system,
		},
	}
}

func searchClusterNodeDiagnostic(system, displayName string, err error, summary openSearchNodeSummary) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := displayName + " aggregate node capacity discovery completed"
	resourceCount := summary.Successful
	if err != nil {
		status = model.ExecutionStatusWarning
		message = displayName + " aggregate node stats endpoint is unavailable; cluster health discovery continued"
		resourceCount = 0
	} else if summary.Failed > 0 || (summary.Total > 0 && summary.Successful < summary.Total) {
		status = model.ExecutionStatusWarning
		message = displayName + " aggregate node stats discovery completed with failed nodes"
	}
	return model.Diagnostic{
		ID:            system + "_node_stats",
		Name:          displayName + " aggregate node capacity",
		Status:        status,
		Message:       message,
		ResourceCount: resourceCount,
		Metadata: map[string]string{
			"endpoint": "/_nodes/stats/fs,jvm,process",
			"optional": "true",
			"system":   system,
		},
	}
}

func nonNegativeInt64(value string) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}
