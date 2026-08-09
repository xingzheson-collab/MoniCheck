package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"monicheck/internal/model"
)

const (
	skyWalkingSystem            = "skywalking"
	defaultSkyWalkingLookback   = time.Hour
	defaultSkyWalkingLimit      = 1000
	defaultSkyWalkingAlarmLimit = 1000
	maxSkyWalkingLimit          = 10000
	skyWalkingAlarmPageSize     = 500
	maxSkyWalkingResponseSize   = 16 << 20
)

const skyWalkingCatalogQuery = `query MoniCheckCatalog {
  listServices {
    id
    name
    group
    shortName
    layers
    normal
  }
  getTimeInfo {
    timezone
    currentTimestamp
  }
}`

const skyWalkingTopologyQuery = `query MoniCheckTopology($duration: Duration!) {
  getGlobalTopology(duration: $duration) {
    nodes {
      id
      name
      type
      isReal
      layers
    }
    calls {
      source
      target
      detectPoints
    }
  }
}`

const skyWalkingServiceDetailsQuery = `query MoniCheckServiceDetails($duration: Duration!, $serviceId: ID!, $endpointLimit: Int!) {
  listInstances(duration: $duration, serviceId: $serviceId) {
    id
    name
    language
  }
  findEndpoint(serviceId: $serviceId, limit: $endpointLimit, duration: $duration) {
    id
    name
  }
}`

const skyWalkingAlarmQuery = `query MoniCheckAlarms($duration: Duration!, $pageNum: Int!, $pageSize: Int!) {
  getAlarm(duration: $duration, paging: {pageNum: $pageNum, pageSize: $pageSize}) {
    msgs {
      id
      name
      message
      startTime
      recoveryTime
      scope
      tags {
        key
        value
      }
    }
  }
}`

const skyWalkingHealthQuery = `query MoniCheckHealth {
  checkHealth {
    score
  }
}`

type SkyWalkingConnector struct {
	baseURL       string
	graphqlPath   string
	client        *http.Client
	lookback      time.Duration
	endpointLimit int
	alarmLimit    int
	detailWorkers int
}

type skyWalkingService struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Group     string   `json:"group"`
	ShortName string   `json:"shortName"`
	Layers    []string `json:"layers"`
	Normal    *bool    `json:"normal"`
}

type skyWalkingInstance struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Language string `json:"language"`
}

type skyWalkingEndpoint struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type skyWalkingServiceDetails struct {
	Instances []skyWalkingInstance `json:"listInstances"`
	Endpoints []skyWalkingEndpoint `json:"findEndpoint"`
}

type skyWalkingTopology struct {
	Nodes []struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Type   string   `json:"type"`
		IsReal bool     `json:"isReal"`
		Layers []string `json:"layers"`
	} `json:"nodes"`
	Calls []struct {
		Source       string   `json:"source"`
		Target       string   `json:"target"`
		DetectPoints []string `json:"detectPoints"`
	} `json:"calls"`
}

type skyWalkingAlarm struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Message      string `json:"message"`
	StartTime    int64  `json:"startTime"`
	RecoveryTime *int64 `json:"recoveryTime"`
	Scope        string `json:"scope"`
	Tags         []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

type skyWalkingHealth struct {
	Available  bool
	Healthy    bool
	StatusCode int
	RequestErr bool
	Source     string
	Score      int
	ScoreSet   bool
	GraphQLErr bool
}

func NewSkyWalkingConnectorWithOptions(baseURL string, graphqlPath string, lookback time.Duration, endpointLimit int, options HTTPOptions) (*SkyWalkingConnector, error) {
	return NewSkyWalkingConnectorWithGovernanceOptions(baseURL, graphqlPath, lookback, endpointLimit, defaultSkyWalkingAlarmLimit, options)
}

func NewSkyWalkingConnectorWithGovernanceOptions(baseURL string, graphqlPath string, lookback time.Duration, endpointLimit int, alarmLimit int, options HTTPOptions) (*SkyWalkingConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("skywalking url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid skywalking url %q: %w", baseURL, err)
	}
	graphqlPath = strings.TrimSpace(graphqlPath)
	if graphqlPath == "" {
		graphqlPath = "/graphql"
	}
	if !strings.HasPrefix(graphqlPath, "/") {
		graphqlPath = "/" + graphqlPath
	}
	if lookback <= 0 {
		lookback = defaultSkyWalkingLookback
	}
	if endpointLimit <= 0 {
		endpointLimit = defaultSkyWalkingLimit
	}
	if endpointLimit > maxSkyWalkingLimit {
		return nil, fmt.Errorf("skywalking endpoint limit %d exceeds maximum %d", endpointLimit, maxSkyWalkingLimit)
	}
	if alarmLimit <= 0 {
		alarmLimit = defaultSkyWalkingAlarmLimit
	}
	if alarmLimit > maxSkyWalkingLimit {
		return nil, fmt.Errorf("skywalking alarm limit %d exceeds maximum %d", alarmLimit, maxSkyWalkingLimit)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &SkyWalkingConnector{
		baseURL:       baseURL,
		graphqlPath:   graphqlPath,
		client:        client,
		lookback:      lookback,
		endpointLimit: endpointLimit,
		alarmLimit:    alarmLimit,
		detailWorkers: defaultConnectorDetailWorkers,
	}, nil
}

func (c *SkyWalkingConnector) ID() string {
	return skyWalkingSystem
}

func (c *SkyWalkingConnector) Name() string {
	return "SkyWalking Connector"
}

func (c *SkyWalkingConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	var catalog struct {
		Services []skyWalkingService `json:"listServices"`
		TimeInfo struct {
			Timezone         string `json:"timezone"`
			CurrentTimestamp int64  `json:"currentTimestamp"`
		} `json:"getTimeInfo"`
	}
	if err := c.graphql(ctx, "catalog", skyWalkingCatalogQuery, nil, &catalog); err != nil {
		return Snapshot{}, err
	}
	services := uniqueSkyWalkingServices(catalog.Services)
	duration := skyWalkingDuration(catalog.TimeInfo.CurrentTimestamp, catalog.TimeInfo.Timezone, c.lookback)
	health := c.health(ctx)

	details, workerCount := boundedDetailFetch(ctx, len(services), c.detailWorkers, func(ctx context.Context, index int) (skyWalkingServiceDetails, error) {
		var detail skyWalkingServiceDetails
		err := c.graphql(ctx, "service details", skyWalkingServiceDetailsQuery, map[string]any{
			"duration":      duration,
			"serviceId":     services[index].ID,
			"endpointLimit": c.endpointLimit,
		}, &detail)
		return detail, err
	})

	var topologyData struct {
		Topology *skyWalkingTopology `json:"getGlobalTopology"`
	}
	topologyErr := c.graphql(ctx, "global topology", skyWalkingTopologyQuery, map[string]any{"duration": duration}, &topologyData)
	if topologyErr == nil && topologyData.Topology == nil {
		topologyErr = fmt.Errorf("skywalking global topology returned no topology")
	}
	alarms, alarmsTruncated, alarmErr := c.fetchAlarms(ctx, duration)

	resources := make(map[string]model.Resource)
	relationships := make(map[string]model.Relationship)
	serviceResourceIDs := make(map[string]string)
	serviceNames := make(map[string][]string)
	instanceNames := make(map[string][]string)
	endpointNames := make(map[string][]string)
	resourceServiceIDs := make(map[string]string)
	failedDetails := 0
	truncatedDetails := 0
	if health.Available {
		runtime := c.resource(model.ResourceTypeInstance, "SkyWalking OAP Runtime", "oap-runtime", now)
		runtime.Metadata = map[string]string{
			model.MetadataSkyWalkingRuntime:         "true",
			model.MetadataSkyWalkingHealthAvailable: "true",
			model.MetadataSkyWalkingHealthy:         strconv.FormatBool(health.Healthy),
			model.MetadataSkyWalkingHealthSource:    health.Source,
		}
		if health.ScoreSet {
			runtime.Metadata[model.MetadataSkyWalkingHealthScore] = strconv.Itoa(health.Score)
		}
		resources[runtime.ID] = runtime
	}
	for index, service := range services {
		serviceResource := c.serviceResource(service.ID, service.Name, now)
		serviceResource.Metadata[model.MetadataAPMCatalogService] = "true"
		serviceResource.Metadata[model.MetadataAPMLookback] = c.lookback.String()
		setOptionalMetadata(serviceResource.Metadata, model.MetadataAPMGroup, service.Group)
		setOptionalMetadata(serviceResource.Metadata, model.MetadataAPMShortName, service.ShortName)
		setStringSliceMetadata(serviceResource.Metadata, model.MetadataAPMLayer, service.Layers)
		if service.Normal != nil {
			serviceResource.Metadata[model.MetadataAPMNormal] = strconv.FormatBool(*service.Normal)
		}
		serviceResourceIDs[service.ID] = serviceResource.ID
		serviceNames[service.Name] = appendUniqueString(serviceNames[service.Name], serviceResource.ID)

		detail := details[index]
		if detail.Err != nil {
			failedDetails++
			serviceResource.Metadata[model.MetadataAPMInstanceDiscoveryAvailable] = "false"
			serviceResource.Metadata[model.MetadataAPMEndpointDiscoveryAvailable] = "false"
			resources[serviceResource.ID] = serviceResource
			continue
		}
		instances := uniqueSkyWalkingInstances(detail.Value.Instances)
		endpoints := uniqueSkyWalkingEndpoints(detail.Value.Endpoints)
		serviceResource.Metadata[model.MetadataAPMInstanceDiscoveryAvailable] = "true"
		serviceResource.Metadata[model.MetadataAPMEndpointDiscoveryAvailable] = "true"
		serviceResource.Metadata[model.MetadataAPMInstanceCount] = strconv.Itoa(len(instances))
		serviceResource.Metadata[model.MetadataAPMEndpointCount] = strconv.Itoa(len(endpoints))
		serviceResource.Metadata[model.MetadataOperationDiscoveryAvailable] = "true"
		serviceResource.Metadata[model.MetadataOperationCount] = strconv.Itoa(len(endpoints))
		serviceResource.Metadata[model.MetadataAPMEndpointLimit] = strconv.Itoa(c.endpointLimit)
		if len(detail.Value.Endpoints) >= c.endpointLimit {
			truncatedDetails++
			serviceResource.Metadata[model.MetadataAPMEndpointDiscoveryTruncated] = "true"
			serviceResource.Metadata[model.MetadataTruncated] = "true"
		}
		resources[serviceResource.ID] = serviceResource

		for _, instance := range instances {
			instanceResource := c.resource(model.ResourceTypeInstance, instance.Name, "instance:"+instance.ID, now)
			instanceResource.Labels = map[string]string{model.MetadataService: service.Name}
			instanceResource.Metadata = map[string]string{model.MetadataService: service.Name}
			setOptionalMetadata(instanceResource.Metadata, model.MetadataAPMLanguage, instance.Language)
			resources[instanceResource.ID] = instanceResource
			instanceNames[instance.Name] = appendUniqueString(instanceNames[instance.Name], instanceResource.ID)
			resourceServiceIDs[instanceResource.ID] = serviceResource.ID
			relationship := c.relationship(instanceResource.ID, serviceResource.ID, model.RelationshipBelongsTo, now)
			relationships[relationship.ID] = relationship
		}
		for _, endpoint := range endpoints {
			endpointResource := c.resource(model.ResourceTypeTraceOperation, service.Name+" "+endpoint.Name, "service:"+service.ID+":endpoint:"+endpoint.ID, now)
			endpointResource.Labels = map[string]string{model.MetadataService: service.Name}
			endpointResource.Metadata = map[string]string{
				model.MetadataService:        service.Name,
				model.MetadataTraceService:   service.Name,
				model.MetadataTraceOperation: endpoint.Name,
			}
			resources[endpointResource.ID] = endpointResource
			endpointNames[endpoint.Name] = appendUniqueString(endpointNames[endpoint.Name], endpointResource.ID)
			resourceServiceIDs[endpointResource.ID] = serviceResource.ID
			relationship := c.relationship(endpointResource.ID, serviceResource.ID, model.RelationshipBelongsTo, now)
			relationships[relationship.ID] = relationship
		}
	}

	if topologyErr == nil {
		for _, node := range topologyData.Topology.Nodes {
			serviceResource, ok := c.topologyServiceResource(node.ID, node.Name, node.Type, node.IsReal, node.Layers, resources, now)
			if !ok {
				continue
			}
			serviceResource.Metadata[model.MetadataAPMTopologyDiscoveryAvailable] = "true"
			resources[serviceResource.ID] = serviceResource
			serviceResourceIDs[node.ID] = serviceResource.ID
			serviceNames[serviceResource.Name] = appendUniqueString(serviceNames[serviceResource.Name], serviceResource.ID)
		}
		for _, call := range topologyData.Topology.Calls {
			fromID := serviceResourceIDs[strings.TrimSpace(call.Source)]
			toID := serviceResourceIDs[strings.TrimSpace(call.Target)]
			if fromID == "" || toID == "" || fromID == toID {
				continue
			}
			relationship := c.relationship(fromID, toID, model.RelationshipDependsOn, now)
			if existing, ok := relationships[relationship.ID]; ok {
				count, _ := strconv.Atoi(existing.Metadata[model.MetadataAPMTopologyCallCount])
				existing.Metadata[model.MetadataAPMTopologyCallCount] = strconv.Itoa(count + 1)
				relationships[relationship.ID] = existing
				continue
			}
			relationship.Metadata = map[string]string{
				model.MetadataAPMTopologyCallCount:        "1",
				model.MetadataAPMTopologyDetectPointCount: strconv.Itoa(len(uniqueNonEmptyStrings(call.DetectPoints))),
			}
			relationships[relationship.ID] = relationship
		}
	}

	for _, resource := range resources {
		if resource.Type != model.ResourceTypeService || resource.Source.System != skyWalkingSystem {
			continue
		}
		if resource.Metadata == nil {
			resource.Metadata = map[string]string{}
		}
		resource.Metadata[model.MetadataAPMAlarmLimit] = strconv.Itoa(c.alarmLimit)
		if alarmErr != nil {
			resource.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] = "false"
		} else {
			resource.Metadata[model.MetadataAPMAlarmDiscoveryAvailable] = "true"
			resource.Metadata[model.MetadataAPMAlarmCount] = "0"
			resource.Metadata[model.MetadataAPMActiveAlarmCount] = "0"
			resource.Metadata[model.MetadataAPMRecoveredAlarmCount] = "0"
			if alarmsTruncated {
				resource.Metadata[model.MetadataAPMAlarmDiscoveryTruncated] = "true"
			}
		}
		resources[resource.ID] = resource
	}
	if alarmErr == nil {
		for _, alarm := range alarms {
			alertResource := c.alarmResource(alarm, now)
			targetIDs := skyWalkingAlarmTargetIDs(alarm, serviceNames, instanceNames, endpointNames)
			var serviceID string
			if len(targetIDs) == 1 {
				targetID := targetIDs[0]
				reference := c.relationship(alertResource.ID, targetID, model.RelationshipReferences, now)
				relationships[reference.ID] = reference
				if resources[targetID].Type == model.ResourceTypeService {
					serviceID = targetID
				} else {
					serviceID = resourceServiceIDs[targetID]
				}
			}
			if serviceID != "" {
				if targetIDs[0] != serviceID {
					reference := c.relationship(alertResource.ID, serviceID, model.RelationshipReferences, now)
					relationships[reference.ID] = reference
				}
				service := resources[serviceID]
				alertResource.Labels[model.MetadataService] = service.Name
				alertResource.Metadata[model.MetadataService] = service.Name
				incrementSkyWalkingAlarmCounts(&service, alertResource.Metadata[model.MetadataAlertState])
				resources[serviceID] = service
			}
			resources[alertResource.ID] = alertResource
		}
	}

	detailDiagnostic := detailDiscoveryDiagnostic("skywalking_service_details", "SkyWalking service detail", skyWalkingSystem, c.graphqlPath, len(services), failedDetails)
	addDetailDiscoveryWorkerCount(&detailDiagnostic, workerCount)
	topologyFailed := 0
	if topologyErr != nil {
		topologyFailed = 1
	}
	topologyDiagnostic := detailDiscoveryDiagnostic("skywalking_global_topology", "SkyWalking global topology", skyWalkingSystem, c.graphqlPath, 1, topologyFailed)
	alarmFailed := 0
	if alarmErr != nil {
		alarmFailed = 1
	}
	alarmDiagnostic := detailDiscoveryDiagnostic("skywalking_alarms", "SkyWalking alarm discovery", skyWalkingSystem, c.graphqlPath, 1, alarmFailed)
	alarmDiagnostic.Metadata["alarm_limit"] = strconv.Itoa(c.alarmLimit)
	alarmDiagnostic.Metadata["alarm_count"] = strconv.Itoa(len(alarms))
	if alarmsTruncated {
		alarmDiagnostic.Status = model.ExecutionStatusWarning
		alarmDiagnostic.Message = fmt.Sprintf("SkyWalking alarm discovery reached the configured limit of %d", c.alarmLimit)
		alarmDiagnostic.Metadata["truncated"] = "true"
	}
	if truncatedDetails > 0 {
		detailDiagnostic.Status = model.ExecutionStatusWarning
		detailDiagnostic.Message = fmt.Sprintf("SkyWalking endpoint discovery reached the configured limit for %d of %d services", truncatedDetails, len(services))
		detailDiagnostic.Metadata["truncated_count"] = strconv.Itoa(truncatedDetails)
		detailDiagnostic.Metadata["endpoint_limit"] = strconv.Itoa(c.endpointLimit)
	}
	healthDiagnostic := skyWalkingHealthDiagnostic(health)

	return Snapshot{
		Resources:     sortedSkyWalkingResources(resources),
		Relationships: sortedSkyWalkingRelationships(relationships),
		Diagnostics:   []model.Diagnostic{detailDiagnostic, topologyDiagnostic, alarmDiagnostic, healthDiagnostic},
		Partial:       failedDetails > 0 || topologyErr != nil || truncatedDetails > 0 || alarmErr != nil || alarmsTruncated || !health.Available,
	}, nil
}

func (c *SkyWalkingConnector) health(ctx context.Context) skyWalkingHealth {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthcheck", nil)
	if err != nil {
		return c.graphqlHealth(ctx, 0, true)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return c.graphqlHealth(ctx, 0, true)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	switch response.StatusCode {
	case http.StatusOK:
		return skyWalkingHealth{Available: true, Healthy: true, StatusCode: response.StatusCode, Source: "http"}
	case http.StatusServiceUnavailable:
		return skyWalkingHealth{Available: true, Healthy: false, StatusCode: response.StatusCode, Source: "http"}
	default:
		return c.graphqlHealth(ctx, response.StatusCode, false)
	}
}

func (c *SkyWalkingConnector) graphqlHealth(ctx context.Context, statusCode int, requestErr bool) skyWalkingHealth {
	var data struct {
		Health *struct {
			Score int `json:"score"`
		} `json:"checkHealth"`
	}
	if err := c.graphql(ctx, "health", skyWalkingHealthQuery, nil, &data); err != nil || data.Health == nil {
		return skyWalkingHealth{
			StatusCode: statusCode,
			RequestErr: requestErr,
			GraphQLErr: true,
		}
	}
	return skyWalkingHealth{
		Available:  true,
		Healthy:    data.Health.Score == 0,
		StatusCode: statusCode,
		RequestErr: requestErr,
		Source:     "graphql",
		Score:      data.Health.Score,
		ScoreSet:   true,
	}
}

func skyWalkingHealthDiagnostic(health skyWalkingHealth) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "SkyWalking OAP health discovery completed"
	if health.Available && !health.Healthy {
		status = model.ExecutionStatusWarning
		if health.Source == "graphql" {
			message = "SkyWalking GraphQL health query reports the OAP runtime is unhealthy"
		} else {
			message = "SkyWalking health endpoint reports the OAP runtime is unhealthy"
		}
	} else if !health.Available {
		status = model.ExecutionStatusWarning
		message = "SkyWalking health endpoint is unavailable; APM catalog discovery continued"
	}
	metadata := map[string]string{
		"endpoint":  "/healthcheck",
		"optional":  "true",
		"system":    skyWalkingSystem,
		"available": strconv.FormatBool(health.Available),
	}
	if health.Available {
		metadata["healthy"] = strconv.FormatBool(health.Healthy)
		metadata["source"] = health.Source
	}
	if health.ScoreSet {
		metadata["score"] = strconv.Itoa(health.Score)
	}
	if health.StatusCode != 0 {
		metadata["status_code"] = strconv.Itoa(health.StatusCode)
	}
	if health.RequestErr {
		metadata["request_error"] = "true"
	}
	if health.GraphQLErr {
		metadata["graphql_error"] = "true"
	}
	return model.Diagnostic{
		ID:       "skywalking_oap_health",
		Name:     "SkyWalking OAP health",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

func (c *SkyWalkingConnector) fetchAlarms(ctx context.Context, duration map[string]any) ([]skyWalkingAlarm, bool, error) {
	alarms := make([]skyWalkingAlarm, 0)
	rawCount := 0
	for pageNum := 1; rawCount < c.alarmLimit; pageNum++ {
		pageSize := min(skyWalkingAlarmPageSize, c.alarmLimit-rawCount)
		var data struct {
			Alarms *struct {
				Messages []skyWalkingAlarm `json:"msgs"`
			} `json:"getAlarm"`
		}
		err := c.graphql(ctx, "alarms", skyWalkingAlarmQuery, map[string]any{
			"duration": duration,
			"pageNum":  pageNum,
			"pageSize": pageSize,
		}, &data)
		if err != nil {
			return nil, false, err
		}
		if data.Alarms == nil {
			return nil, false, fmt.Errorf("skywalking alarms returned no alarm collection")
		}
		messages := data.Alarms.Messages
		remaining := c.alarmLimit - rawCount
		if len(messages) > remaining {
			messages = messages[:remaining]
		}
		alarms = append(alarms, messages...)
		rawCount += len(messages)
		if len(data.Alarms.Messages) < pageSize {
			return uniqueSkyWalkingAlarms(alarms), false, nil
		}
		if rawCount >= c.alarmLimit {
			return uniqueSkyWalkingAlarms(alarms), true, nil
		}
	}
	return uniqueSkyWalkingAlarms(alarms), true, nil
}

func uniqueSkyWalkingAlarms(values []skyWalkingAlarm) []skyWalkingAlarm {
	seen := make(map[string]bool)
	result := make([]skyWalkingAlarm, 0, len(values))
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Name = strings.TrimSpace(value.Name)
		value.Scope = strings.TrimSpace(value.Scope)
		if value.ID == "" || seen[value.ID] {
			continue
		}
		seen[value.ID] = true
		result = append(result, value)
	}
	return result
}

func (c *SkyWalkingConnector) alarmResource(alarm skyWalkingAlarm, now time.Time) model.Resource {
	name := strings.TrimSpace(alarm.Name)
	if name == "" {
		name = alarm.ID
	}
	resource := c.resource(model.ResourceTypeAlert, name, "alarm:"+alarm.ID, now)
	resource.Labels = map[string]string{}
	resource.Metadata = map[string]string{
		model.MetadataAPMAlarmScope:    strings.TrimSpace(alarm.Scope),
		model.MetadataAPMAlarmTagCount: strconv.Itoa(len(alarm.Tags)),
		model.MetadataAlertState:       "active",
	}
	setOptionalMetadata(resource.Metadata, model.MetadataDescription, truncateSkyWalkingText(strings.TrimSpace(alarm.Message), 512))
	if alarm.StartTime > 0 {
		startedAt := time.UnixMilli(alarm.StartTime).UTC()
		resource.Metadata[model.MetadataStartsAt] = startedAt.Format(time.RFC3339)
		resource.Metadata[model.MetadataUpdatedAt] = startedAt.Format(time.RFC3339)
	}
	if alarm.RecoveryTime != nil && *alarm.RecoveryTime > 0 {
		recoveredAt := time.UnixMilli(*alarm.RecoveryTime).UTC()
		resource.Metadata[model.MetadataAlertState] = "recovered"
		resource.Metadata[model.MetadataEndsAt] = recoveredAt.Format(time.RFC3339)
		resource.Metadata[model.MetadataUpdatedAt] = recoveredAt.Format(time.RFC3339)
	}
	tagKeys := make([]string, 0, len(alarm.Tags))
	for _, tag := range alarm.Tags {
		key := strings.TrimSpace(tag.Key)
		if key == "" {
			continue
		}
		tagKeys = append(tagKeys, key)
		if strings.EqualFold(key, "severity") {
			if severity := skyWalkingSeverity(tag.Value); severity != "" {
				resource.Labels["severity"] = severity
			}
		}
	}
	tagKeys = uniqueNonEmptyStrings(tagKeys)
	sort.Strings(tagKeys)
	if len(tagKeys) > 0 {
		resource.Metadata[model.MetadataAPMAlarmTagKeys] = strings.Join(tagKeys, ",")
	}
	return resource
}

func skyWalkingSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "error", "warning", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func skyWalkingAlarmTargetIDs(alarm skyWalkingAlarm, serviceNames map[string][]string, instanceNames map[string][]string, endpointNames map[string][]string) []string {
	name := strings.TrimSpace(alarm.Name)
	switch strings.ToLower(strings.TrimSpace(alarm.Scope)) {
	case "service":
		return serviceNames[name]
	case "serviceinstance":
		return instanceNames[name]
	case "endpoint":
		return endpointNames[name]
	default:
		return nil
	}
}

func incrementSkyWalkingAlarmCounts(service *model.Resource, state string) {
	total, _ := strconv.Atoi(service.Metadata[model.MetadataAPMAlarmCount])
	service.Metadata[model.MetadataAPMAlarmCount] = strconv.Itoa(total + 1)
	if state == "recovered" {
		recovered, _ := strconv.Atoi(service.Metadata[model.MetadataAPMRecoveredAlarmCount])
		service.Metadata[model.MetadataAPMRecoveredAlarmCount] = strconv.Itoa(recovered + 1)
		return
	}
	active, _ := strconv.Atoi(service.Metadata[model.MetadataAPMActiveAlarmCount])
	service.Metadata[model.MetadataAPMActiveAlarmCount] = strconv.Itoa(active + 1)
}

func truncateSkyWalkingText(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	end := 0
	for index, current := range value {
		size := utf8.RuneLen(current)
		if index+size > limit {
			break
		}
		end = index + size
	}
	return value[:end]
}

func (c *SkyWalkingConnector) graphql(ctx context.Context, operation string, query string, variables map[string]any, target any) error {
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+c.graphqlPath, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request = markRequestIdempotent(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("skywalking %s request: %w", operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("skywalking %s request failed with status %d", operation, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSkyWalkingResponseSize+1))
	if err != nil {
		return fmt.Errorf("read skywalking %s response: %w", operation, err)
	}
	if len(data) > maxSkyWalkingResponseSize {
		return fmt.Errorf("skywalking %s response exceeds %d bytes", operation, maxSkyWalkingResponseSize)
	}
	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode skywalking %s response: %w", operation, err)
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("skywalking %s returned %d graphql errors", operation, len(envelope.Errors))
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return fmt.Errorf("skywalking %s returned no data", operation)
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return fmt.Errorf("decode skywalking %s data: %w", operation, err)
	}
	return nil
}

func skyWalkingDuration(currentTimestamp int64, timezone string, lookback time.Duration) map[string]any {
	now := time.Now().UTC()
	if currentTimestamp > 0 {
		now = time.UnixMilli(currentTimestamp)
	}
	location := skyWalkingLocation(timezone)
	now = now.In(location)
	return map[string]any{
		"start": now.Add(-lookback).Format("2006-01-02 1504"),
		"end":   now.Format("2006-01-02 1504"),
		"step":  "MINUTE",
	}
}

func skyWalkingLocation(value string) *time.Location {
	value = strings.TrimSpace(value)
	if len(value) != 5 || (value[0] != '+' && value[0] != '-') {
		return time.UTC
	}
	hours, hourErr := strconv.Atoi(value[1:3])
	minutes, minuteErr := strconv.Atoi(value[3:5])
	if hourErr != nil || minuteErr != nil || hours > 23 || minutes > 59 {
		return time.UTC
	}
	offset := (hours*60 + minutes) * 60
	if value[0] == '-' {
		offset = -offset
	}
	return time.FixedZone("SkyWalking", offset)
}

func uniqueSkyWalkingServices(values []skyWalkingService) []skyWalkingService {
	seen := make(map[string]bool)
	result := make([]skyWalkingService, 0, len(values))
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Name = strings.TrimSpace(value.Name)
		if value.ID == "" || value.Name == "" || seen[value.ID] {
			continue
		}
		seen[value.ID] = true
		result = append(result, value)
	}
	return result
}

func uniqueSkyWalkingInstances(values []skyWalkingInstance) []skyWalkingInstance {
	seen := make(map[string]bool)
	result := make([]skyWalkingInstance, 0, len(values))
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Name = strings.TrimSpace(value.Name)
		if value.ID == "" || value.Name == "" || seen[value.ID] {
			continue
		}
		seen[value.ID] = true
		result = append(result, value)
	}
	return result
}

func uniqueSkyWalkingEndpoints(values []skyWalkingEndpoint) []skyWalkingEndpoint {
	seen := make(map[string]bool)
	result := make([]skyWalkingEndpoint, 0, len(values))
	for _, value := range values {
		value.ID = strings.TrimSpace(value.ID)
		value.Name = strings.TrimSpace(value.Name)
		if value.ID == "" || value.Name == "" || seen[value.ID] {
			continue
		}
		seen[value.ID] = true
		result = append(result, value)
	}
	return result
}

func (c *SkyWalkingConnector) serviceResource(id string, name string, now time.Time) model.Resource {
	resource := c.resource(model.ResourceTypeService, strings.TrimSpace(name), "service:"+strings.TrimSpace(id), now)
	resource.Labels = map[string]string{model.MetadataService: resource.Name}
	resource.Metadata = map[string]string{model.MetadataService: resource.Name}
	return resource
}

func (c *SkyWalkingConnector) topologyServiceResource(id string, name string, componentType string, real bool, layers []string, resources map[string]model.Resource, now time.Time) (model.Resource, bool) {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	if id == "" || name == "" {
		return model.Resource{}, false
	}
	resource := c.serviceResource(id, name, now)
	if existing, ok := resources[resource.ID]; ok {
		resource = existing
	}
	if resource.Metadata == nil {
		resource.Metadata = map[string]string{}
	}
	resource.Metadata[model.MetadataAPMReal] = strconv.FormatBool(real)
	setOptionalMetadata(resource.Metadata, model.MetadataAPMType, componentType)
	setStringSliceMetadata(resource.Metadata, model.MetadataAPMLayer, layers)
	return resource, true
}

func (c *SkyWalkingConnector) resource(resourceType model.ResourceType, name string, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", skyWalkingSystem, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     skyWalkingSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *SkyWalkingConnector) relationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", skyWalkingSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}

func setOptionalMetadata(metadata map[string]string, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		metadata[key] = value
	}
}

func setStringSliceMetadata(metadata map[string]string, key string, values []string) {
	existing := strings.Split(metadata[key], ",")
	values = uniqueNonEmptyStrings(append(existing, values...))
	if len(values) > 0 {
		metadata[key] = strings.Join(values, ",")
	}
}

func sortedSkyWalkingResources(values map[string]model.Resource) []model.Resource {
	result := make([]model.Resource, 0, len(values))
	for _, resource := range values {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func sortedSkyWalkingRelationships(values map[string]model.Relationship) []model.Relationship {
	result := make([]model.Relationship, 0, len(values))
	for _, relationship := range values {
		result = append(result, relationship)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
