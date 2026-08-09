package connector

import (
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

	"monicheck/internal/model"
)

const (
	jaegerSystem                    = "jaeger"
	defaultJaegerOperationLimit     = 1000
	maxJaegerOperationLimit         = 10000
	defaultJaegerDependencyLookback = 24 * time.Hour
	defaultJaegerDependencyLimit    = 5000
	maxJaegerDependencyLimit        = 100000
)

type JaegerConnector struct {
	baseURL            string
	healthURL          string
	client             *http.Client
	healthClient       *http.Client
	operationLimit     int
	dependencyLookback time.Duration
	dependencyLimit    int
	topologyEnabled    bool
	detailWorkers      int
}

func NewJaegerConnectorWithOptions(baseURL string, options HTTPOptions) (*JaegerConnector, error) {
	return newJaegerConnector(baseURL, "", defaultJaegerOperationLimit, 0, defaultJaegerDependencyLimit, false, options)
}

func NewJaegerConnectorWithGovernanceOptions(baseURL string, operationLimit int, options HTTPOptions) (*JaegerConnector, error) {
	return newJaegerConnector(baseURL, "", operationLimit, 0, defaultJaegerDependencyLimit, false, options)
}

func NewJaegerConnectorWithTopologyOptions(baseURL string, operationLimit int, dependencyLookback time.Duration, dependencyLimit int, options HTTPOptions) (*JaegerConnector, error) {
	return newJaegerConnector(baseURL, "", operationLimit, dependencyLookback, dependencyLimit, true, options)
}

func NewJaegerConnectorWithRuntimeOptions(baseURL string, healthURL string, operationLimit int, dependencyLookback time.Duration, dependencyLimit int, options HTTPOptions) (*JaegerConnector, error) {
	return newJaegerConnector(baseURL, healthURL, operationLimit, dependencyLookback, dependencyLimit, true, options)
}

func newJaegerConnector(baseURL string, healthURL string, operationLimit int, dependencyLookback time.Duration, dependencyLimit int, topologyEnabled bool, options HTTPOptions) (*JaegerConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("jaeger url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid jaeger url %q: %w", baseURL, err)
	}
	healthURL = strings.TrimSpace(healthURL)
	if healthURL != "" {
		parsed, err := url.ParseRequestURI(healthURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid jaeger health url %q", healthURL)
		}
	}
	if operationLimit <= 0 {
		operationLimit = defaultJaegerOperationLimit
	}
	if operationLimit > maxJaegerOperationLimit {
		return nil, fmt.Errorf("jaeger operation limit must not exceed %d", maxJaegerOperationLimit)
	}
	if topologyEnabled && dependencyLookback <= 0 {
		dependencyLookback = defaultJaegerDependencyLookback
	}
	if dependencyLimit <= 0 {
		dependencyLimit = defaultJaegerDependencyLimit
	}
	if dependencyLimit > maxJaegerDependencyLimit {
		return nil, fmt.Errorf("jaeger dependency limit must not exceed %d", maxJaegerDependencyLimit)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	healthOptions := options
	healthOptions.BearerToken = ""
	healthOptions.Username = ""
	healthOptions.Password = ""
	healthOptions.APIKey = ""
	healthOptions.Headers = nil
	healthClient, err := NewHTTPClient(healthOptions)
	if err != nil {
		return nil, err
	}
	return &JaegerConnector{
		baseURL:            baseURL,
		healthURL:          healthURL,
		client:             client,
		healthClient:       healthClient,
		operationLimit:     operationLimit,
		dependencyLookback: dependencyLookback,
		dependencyLimit:    dependencyLimit,
		topologyEnabled:    topologyEnabled,
		detailWorkers:      defaultConnectorDetailWorkers,
	}, nil
}

func (c *JaegerConnector) ID() string {
	return "jaeger"
}

func (c *JaegerConnector) Name() string {
	return "Jaeger Connector"
}

func (c *JaegerConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	services, err := c.services(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	services = uniqueNonEmptyStrings(services)
	details, workerCount := boundedDetailFetch(ctx, len(services), c.detailWorkers, func(ctx context.Context, index int) ([]jaegerOperation, error) {
		return c.operations(ctx, services[index])
	})
	resources := make([]model.Resource, 0, len(services))
	relationships := make([]model.Relationship, 0)
	failedDetailCount := 0
	truncatedServiceCount := 0
	for index, service := range services {
		serviceResource := c.resource(model.ResourceTypeService, service, "service:"+service, now)
		serviceResource.Labels = map[string]string{model.MetadataService: service}
		serviceResource.Metadata = map[string]string{
			model.MetadataService:      service,
			model.MetadataTraceService: service,
		}

		detail := details[index]
		if detail.Err != nil {
			failedDetailCount++
			serviceResource.Metadata[model.MetadataOperationDiscoveryAvailable] = "false"
			resources = append(resources, serviceResource)
			continue
		}
		operations := normalizeJaegerOperations(detail.Value)
		operationCount := len(operations)
		truncated := operationCount > c.operationLimit
		if truncated {
			truncatedServiceCount++
			operations = operations[:c.operationLimit]
		}
		serviceResource.Metadata[model.MetadataOperationDiscoveryAvailable] = "true"
		serviceResource.Metadata[model.MetadataOperationCount] = strconv.Itoa(operationCount)
		serviceResource.Metadata[model.MetadataOperationLimit] = strconv.Itoa(c.operationLimit)
		if truncated {
			serviceResource.Metadata[model.MetadataOperationDiscoveryTruncated] = "true"
		}
		resources = append(resources, serviceResource)
		for _, operation := range operations {
			operationResource := c.resource(model.ResourceTypeTraceOperation, service+" "+operation.Name, "service:"+service+":operation:"+operation.Name, now)
			operationResource.Labels = map[string]string{model.MetadataService: service}
			operationResource.Metadata = map[string]string{
				model.MetadataTraceService:   service,
				model.MetadataTraceOperation: operation.Name,
			}
			if len(operation.Kinds) == 1 {
				operationResource.Metadata[model.MetadataTraceOperationKind] = operation.Kinds[0]
			}
			if len(operation.Kinds) > 0 {
				operationResource.Metadata[model.MetadataTraceOperationKinds] = strings.Join(operation.Kinds, ",")
				operationResource.Metadata[model.MetadataTraceOperationKindCount] = strconv.Itoa(len(operation.Kinds))
			}
			resources = append(resources, operationResource)
			relationships = append(relationships, c.relationship(operationResource.ID, serviceResource.ID, model.RelationshipBelongsTo, now))
		}
	}
	diagnostic := detailDiscoveryDiagnostic("jaeger_operations", "Jaeger operation", jaegerSystem, "/api/operations?service={service}", len(services), failedDetailCount)
	addDetailDiscoveryWorkerCount(&diagnostic, workerCount)
	diagnostic.Metadata["operation_limit"] = strconv.Itoa(c.operationLimit)
	diagnostic.Metadata["truncated_service_count"] = strconv.Itoa(truncatedServiceCount)
	if truncatedServiceCount > 0 {
		diagnostic.Status = model.ExecutionStatusWarning
	}
	diagnostics := []model.Diagnostic{diagnostic}
	health := c.health(ctx)
	if health.Configured {
		diagnostics = append(diagnostics, jaegerHealthDiagnostic(health))
		if health.Available {
			runtime := c.resource(model.ResourceTypeInstance, "Jaeger Runtime", "runtime", now)
			runtime.Metadata = map[string]string{
				model.MetadataJaegerRuntime:         "true",
				model.MetadataJaegerHealthAvailable: "true",
				model.MetadataJaegerHealthy:         strconv.FormatBool(health.Healthy),
				model.MetadataJaegerHealthSource:    health.Source,
			}
			resources = append(resources, runtime)
		}
	}
	topologyPartial := false
	if c.topologyEnabled {
		var topologyDiagnostic model.Diagnostic
		resources, relationships, topologyDiagnostic, topologyPartial = c.enrichDependencies(ctx, now, resources, relationships)
		diagnostics = append(diagnostics, topologyDiagnostic)
	}
	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   diagnostics,
		Partial:       failedDetailCount > 0 || truncatedServiceCount > 0 || topologyPartial || (health.Configured && !health.Available),
	}, nil
}

type jaegerHealth struct {
	Configured bool
	Available  bool
	Healthy    bool
	StatusCode int
	Source     string
	RequestErr bool
}

func (c *JaegerConnector) health(ctx context.Context) jaegerHealth {
	if c.healthURL == "" {
		return jaegerHealth{}
	}
	result := jaegerHealth{Configured: true, Source: "http_status"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL, nil)
	if err != nil {
		result.RequestErr = true
		return result
	}
	response, err := c.healthClient.Do(request)
	if err != nil {
		result.RequestErr = true
		return result
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	switch {
	case response.StatusCode == http.StatusServiceUnavailable:
		result.Available = true
		result.Healthy = false
		return result
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return result
	}
	result.Available = true
	result.Healthy = true
	var payload struct {
		Healthy *bool `json:"healthy"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&payload); err == nil && payload.Healthy != nil {
		result.Healthy = *payload.Healthy
		result.Source = "healthcheckv2"
	}
	return result
}

func jaegerHealthDiagnostic(health jaegerHealth) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "Jaeger health discovery completed"
	if health.Available && !health.Healthy {
		status = model.ExecutionStatusWarning
		message = "Jaeger health endpoint explicitly reports the runtime as unhealthy"
	} else if !health.Available {
		status = model.ExecutionStatusWarning
		message = "Jaeger health endpoint is unavailable; catalog discovery continued"
	}
	metadata := map[string]string{
		"configured": strconv.FormatBool(health.Configured),
		"available":  strconv.FormatBool(health.Available),
		"source":     health.Source,
	}
	if health.Available {
		metadata["healthy"] = strconv.FormatBool(health.Healthy)
	}
	if health.StatusCode != 0 {
		metadata["status_code"] = strconv.Itoa(health.StatusCode)
	}
	if health.RequestErr {
		metadata["request_error"] = "true"
	}
	return model.Diagnostic{
		ID:       "jaeger_health",
		Name:     "Jaeger runtime health",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

type jaegerDependency struct {
	Parent    string `json:"parent"`
	Child     string `json:"child"`
	CallCount uint64 `json:"callCount"`
}

func (c *JaegerConnector) enrichDependencies(ctx context.Context, now time.Time, resources []model.Resource, relationships []model.Relationship) ([]model.Resource, []model.Relationship, model.Diagnostic, bool) {
	dependencies, err := c.dependencies(ctx, now)
	failed := 0
	if err != nil {
		failed = 1
	}
	diagnostic := detailDiscoveryDiagnostic("jaeger_dependencies", "Jaeger service dependency", jaegerSystem, "/api/dependencies?endTs={endTs}&lookback={lookback}", 1, failed)
	diagnostic.Metadata["lookback"] = c.dependencyLookback.String()
	diagnostic.Metadata["dependency_limit"] = strconv.Itoa(c.dependencyLimit)
	if err != nil {
		for index := range resources {
			if resources[index].Type != model.ResourceTypeService || resources[index].Source.System != jaegerSystem {
				continue
			}
			resources[index].Metadata[model.MetadataAPMTopologyDiscoveryAvailable] = "false"
			resources[index].Metadata[model.MetadataAPMLookback] = c.dependencyLookback.String()
		}
		return resources, relationships, diagnostic, true
	}

	dependencies = normalizeJaegerDependencies(dependencies)
	dependencyCount := len(dependencies)
	truncated := dependencyCount > c.dependencyLimit
	if truncated {
		dependencies = dependencies[:c.dependencyLimit]
		diagnostic.Status = model.ExecutionStatusWarning
		diagnostic.Message = fmt.Sprintf("Jaeger dependency discovery reached the configured limit of %d", c.dependencyLimit)
		diagnostic.Metadata["truncated"] = "true"
	}
	diagnostic.Metadata["dependency_count"] = strconv.Itoa(dependencyCount)

	serviceIDs := make(map[string]string)
	for index := range resources {
		if resources[index].Type != model.ResourceTypeService || resources[index].Source.System != jaegerSystem {
			continue
		}
		serviceIDs[resources[index].Metadata[model.MetadataService]] = resources[index].ID
	}
	for _, dependency := range dependencies {
		for _, service := range []string{dependency.Parent, dependency.Child} {
			if serviceIDs[service] != "" {
				continue
			}
			serviceResource := c.resource(model.ResourceTypeService, service, "service:"+service, now)
			serviceResource.Labels = map[string]string{model.MetadataService: service}
			serviceResource.Metadata = map[string]string{
				model.MetadataService:           service,
				model.MetadataTraceService:      service,
				model.MetadataAPMCatalogService: "false",
			}
			serviceIDs[service] = serviceResource.ID
			resources = append(resources, serviceResource)
		}
	}
	for index := range resources {
		if resources[index].Type != model.ResourceTypeService || resources[index].Source.System != jaegerSystem {
			continue
		}
		resources[index].Metadata[model.MetadataAPMTopologyDiscoveryAvailable] = "true"
		resources[index].Metadata[model.MetadataAPMLookback] = c.dependencyLookback.String()
		resources[index].Metadata[model.MetadataAPMTopologyDependencyCount] = strconv.Itoa(dependencyCount)
		resources[index].Metadata[model.MetadataAPMTopologyDependencyLimit] = strconv.Itoa(c.dependencyLimit)
		if truncated {
			resources[index].Metadata[model.MetadataAPMTopologyDiscoveryTruncated] = "true"
		}
	}
	for _, dependency := range dependencies {
		relationship := c.relationship(serviceIDs[dependency.Parent], serviceIDs[dependency.Child], model.RelationshipDependsOn, now)
		relationship.Metadata = map[string]string{
			model.MetadataAPMTopologyCallCount: strconv.FormatUint(dependency.CallCount, 10),
			model.MetadataAPMLookback:          c.dependencyLookback.String(),
		}
		relationships = append(relationships, relationship)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	sort.Slice(relationships, func(i, j int) bool { return relationships[i].ID < relationships[j].ID })
	return resources, relationships, diagnostic, truncated
}

func (c *JaegerConnector) dependencies(ctx context.Context, now time.Time) ([]jaegerDependency, error) {
	endMillis := now.UnixMilli()
	path := "/api/dependencies?endTs=" + strconv.FormatInt(endMillis, 10) +
		"&lookback=" + strconv.FormatInt(c.dependencyLookback.Milliseconds(), 10)
	var raw json.RawMessage
	if err := c.getJSON(ctx, path, &raw); err != nil {
		return nil, err
	}
	var dependencies []jaegerDependency
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &dependencies); err != nil {
			return nil, fmt.Errorf("decode jaeger dependencies: %w", err)
		}
		return dependencies, nil
	}
	var response struct {
		Data   []jaegerDependency `json:"data"`
		Errors []any              `json:"errors"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode jaeger dependencies: %w", err)
	}
	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("jaeger dependencies failed: %v", response.Errors)
	}
	return response.Data, nil
}

func normalizeJaegerDependencies(dependencies []jaegerDependency) []jaegerDependency {
	counts := make(map[string]uint64, len(dependencies))
	edges := make(map[string]jaegerDependency, len(dependencies))
	for _, dependency := range dependencies {
		parent := strings.TrimSpace(dependency.Parent)
		child := strings.TrimSpace(dependency.Child)
		if parent == "" || child == "" || parent == child {
			continue
		}
		key := parent + "\x00" + child
		edge := jaegerDependency{Parent: parent, Child: child}
		edges[key] = edge
		counts[key] += dependency.CallCount
	}
	result := make([]jaegerDependency, 0, len(edges))
	for key, edge := range edges {
		edge.CallCount = counts[key]
		result = append(result, edge)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Parent != result[j].Parent {
			return result[i].Parent < result[j].Parent
		}
		return result[i].Child < result[j].Child
	})
	return result
}

func (c *JaegerConnector) services(ctx context.Context) ([]string, error) {
	var response struct {
		Data   []string `json:"data"`
		Errors []any    `json:"errors"`
	}
	if err := c.getJSON(ctx, "/api/services", &response); err != nil {
		return nil, err
	}
	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("jaeger services failed: %v", response.Errors)
	}
	return response.Data, nil
}

type jaegerOperation struct {
	Name  string
	Kind  string
	Kinds []string
}

func (c *JaegerConnector) operations(ctx context.Context, service string) ([]jaegerOperation, error) {
	var response struct {
		Data   []json.RawMessage `json:"data"`
		Errors []any             `json:"errors"`
	}
	path := "/api/operations?service=" + url.QueryEscape(service)
	if err := c.getJSON(ctx, path, &response); err != nil {
		return nil, err
	}
	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("jaeger operations for %q failed: %v", service, response.Errors)
	}
	operations := make([]jaegerOperation, 0, len(response.Data))
	for _, item := range response.Data {
		var name string
		if err := json.Unmarshal(item, &name); err == nil {
			operations = append(operations, jaegerOperation{Name: name})
			continue
		}
		var object struct {
			Name     string `json:"name"`
			SpanKind string `json:"spanKind"`
		}
		if err := json.Unmarshal(item, &object); err == nil && object.Name != "" {
			operations = append(operations, jaegerOperation{Name: object.Name, Kind: object.SpanKind})
		}
	}
	return operations, nil
}

func normalizeJaegerOperations(operations []jaegerOperation) []jaegerOperation {
	kindsByName := make(map[string]map[string]bool, len(operations))
	for _, operation := range operations {
		name := strings.TrimSpace(operation.Name)
		if name == "" {
			continue
		}
		if kindsByName[name] == nil {
			kindsByName[name] = map[string]bool{}
		}
		if kind := strings.TrimSpace(operation.Kind); kind != "" {
			kindsByName[name][kind] = true
		}
	}
	names := make([]string, 0, len(kindsByName))
	for name := range kindsByName {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]jaegerOperation, 0, len(names))
	for _, name := range names {
		kinds := make([]string, 0, len(kindsByName[name]))
		for kind := range kindsByName[name] {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		result = append(result, jaegerOperation{Name: name, Kinds: kinds})
	}
	return result
}

func (c *JaegerConnector) getJSON(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("jaeger request %s failed with status %d", path, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func (c *JaegerConnector) resource(resourceType model.ResourceType, name string, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", jaegerSystem, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     jaegerSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *JaegerConnector) relationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", jaegerSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
