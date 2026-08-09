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
	tempoSystem               = "tempo"
	defaultTempoLookback      = 24 * time.Hour
	defaultTempoTagValueLimit = 200
	maxTempoTagValueLimit     = 10000
)

type TempoConnector struct {
	baseURL       string
	client        *http.Client
	lookback      time.Duration
	tagValueLimit int
	detailWorkers int
}

type tempoReadiness struct {
	Available  bool
	Ready      bool
	StatusCode int
	RequestErr bool
}

func NewTempoConnectorWithOptions(baseURL string, options HTTPOptions) (*TempoConnector, error) {
	return NewTempoConnectorWithGovernanceOptions(baseURL, defaultTempoLookback, defaultTempoTagValueLimit, options)
}

func NewTempoConnectorWithGovernanceOptions(baseURL string, lookback time.Duration, tagValueLimit int, options HTTPOptions) (*TempoConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("tempo url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid tempo url %q: %w", baseURL, err)
	}
	if lookback <= 0 {
		lookback = defaultTempoLookback
	}
	if tagValueLimit <= 0 {
		tagValueLimit = defaultTempoTagValueLimit
	}
	if tagValueLimit > maxTempoTagValueLimit {
		return nil, fmt.Errorf("tempo tag value limit must not exceed %d", maxTempoTagValueLimit)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &TempoConnector{
		baseURL:       baseURL,
		client:        client,
		lookback:      lookback,
		tagValueLimit: tagValueLimit,
		detailWorkers: defaultConnectorDetailWorkers,
	}, nil
}

func (c *TempoConnector) ID() string {
	return "tempo"
}

func (c *TempoConnector) Name() string {
	return "Tempo Connector"
}

func (c *TempoConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	start := now.Add(-c.lookback).Unix()
	end := now.Unix()
	tags, err := c.tags(ctx, start, end)
	if err != nil {
		return Snapshot{}, err
	}
	readiness := c.readiness(ctx)
	tags = uniqueNonEmptyStrings(tags)
	details, workerCount := boundedDetailFetch(ctx, len(tags), c.detailWorkers, func(ctx context.Context, index int) ([]string, error) {
		return c.tagValues(ctx, tags[index], start, end)
	})
	resources := make([]model.Resource, 0, len(tags)+1)
	relationships := make([]model.Relationship, 0)
	if readiness.Available {
		runtime := c.resource(model.ResourceTypeInstance, "Tempo Runtime", "runtime", now)
		runtime.Metadata = map[string]string{
			model.MetadataTempoRuntime:            "true",
			model.MetadataTempoReadinessAvailable: "true",
			model.MetadataTempoReady:              strconv.FormatBool(readiness.Ready),
		}
		resources = append(resources, runtime)
	}
	failedDetailCount := 0
	serviceDiscoveryTruncated := false
	traceServiceIDs := make(map[string]bool)
	for index, tag := range tags {
		tagResource := c.resource(model.ResourceTypeTraceTag, tag, "tag:"+tag, now)
		detail := details[index]
		if detail.Err != nil {
			failedDetailCount++
			tagResource.Metadata = map[string]string{
				model.MetadataTraceTag:                tag,
				model.MetadataValueDiscoveryAvailable: "false",
			}
			resources = append(resources, tagResource)
			continue
		}
		discoveredValues := privacySafeDiscoveredValues(tempoSystem, tag, detail.Value)
		truncated := len(discoveredValues) > c.tagValueLimit
		tagResource.Metadata = map[string]string{
			model.MetadataTraceTag:                tag,
			model.MetadataTraceTagValueCount:      fmt.Sprintf("%d", len(discoveredValues)),
			model.MetadataValueDiscoveryAvailable: "true",
			model.MetadataTraceLookback:           c.lookback.String(),
		}
		if truncated {
			tagResource.Metadata[model.MetadataTruncated] = "true"
		}
		sampledValues := discoveredValues
		if truncated {
			sampledValues = discoveredValues[:c.tagValueLimit]
		}
		resources = append(resources, tagResource)
		for _, value := range sampledValues {
			legacyExternalID := "tag:" + tag + ":value:" + value.raw
			valueResource := c.resource(
				model.ResourceTypeTraceTagValue,
				redactedDiscoveredValueName(tag, value.fingerprint),
				legacyExternalID,
				now,
			)
			redactedExternalID := "tag:" + tag + ":value-fingerprint:" + value.fingerprint
			valueResource.UID = redactedExternalID
			valueResource.Source.ExternalID = redactedExternalID
			valueResource.Metadata = map[string]string{
				model.MetadataTraceTag:         tag,
				model.MetadataValueFingerprint: value.fingerprint,
				model.MetadataValueRedacted:    "true",
			}
			if truncated {
				valueResource.Metadata[model.MetadataTruncated] = "true"
			}
			resources = append(resources, valueResource)
			relationships = append(relationships, c.relationship(valueResource.ID, tagResource.ID, model.RelationshipBelongsTo, now))
		}
		if isTempoServiceNameTag(tag) {
			tagResource.Metadata[model.MetadataTraceServiceCount] = strconv.Itoa(len(sampledValues))
			tagResource.Metadata[model.MetadataTraceServiceLimit] = strconv.Itoa(c.tagValueLimit)
			if truncated {
				serviceDiscoveryTruncated = true
				tagResource.Metadata[model.MetadataTraceServiceDiscoveryTruncated] = "true"
			}
			resources[len(resources)-len(sampledValues)-1] = tagResource
			for _, value := range sampledValues {
				serviceResource := c.traceServiceResource(value.raw, tag, now)
				if traceServiceIDs[serviceResource.ID] {
					continue
				}
				traceServiceIDs[serviceResource.ID] = true
				resources = append(resources, serviceResource)
			}
		}
	}
	diagnostic := detailDiscoveryDiagnostic("tempo_tag_values", "Tempo tag value", tempoSystem, "/api/search/tag/{tag}/values", len(tags), failedDetailCount)
	addDetailDiscoveryWorkerCount(&diagnostic, workerCount)
	diagnostic.Metadata["lookback"] = c.lookback.String()
	diagnostic.Metadata["tag_value_limit"] = strconv.Itoa(c.tagValueLimit)
	if serviceDiscoveryTruncated {
		diagnostic.Status = model.ExecutionStatusWarning
		diagnostic.Metadata["service_discovery_truncated"] = "true"
	}
	readinessDiagnostic := tempoReadinessDiagnostic(readiness)
	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   []model.Diagnostic{diagnostic, readinessDiagnostic},
		Partial:       failedDetailCount > 0 || serviceDiscoveryTruncated || !readiness.Available,
	}, nil
}

func (c *TempoConnector) readiness(ctx context.Context) tempoReadiness {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ready", nil)
	if err != nil {
		return tempoReadiness{RequestErr: true}
	}
	response, err := c.client.Do(request)
	if err != nil {
		return tempoReadiness{RequestErr: true}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	switch response.StatusCode {
	case http.StatusOK:
		return tempoReadiness{Available: true, Ready: true, StatusCode: response.StatusCode}
	case http.StatusServiceUnavailable:
		return tempoReadiness{Available: true, Ready: false, StatusCode: response.StatusCode}
	default:
		return tempoReadiness{StatusCode: response.StatusCode}
	}
}

func tempoReadinessDiagnostic(readiness tempoReadiness) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "Tempo readiness discovery completed"
	if readiness.Available && !readiness.Ready {
		status = model.ExecutionStatusWarning
		message = "Tempo readiness endpoint reports the configured service as not ready"
	} else if !readiness.Available {
		status = model.ExecutionStatusWarning
		message = "Tempo readiness endpoint is unavailable; trace tag discovery continued"
	}
	metadata := map[string]string{
		"endpoint":  "/ready",
		"optional":  "true",
		"system":    tempoSystem,
		"available": strconv.FormatBool(readiness.Available),
		"scope":     "configured_service",
	}
	if readiness.Available {
		metadata["ready"] = strconv.FormatBool(readiness.Ready)
	}
	if readiness.StatusCode != 0 {
		metadata["status_code"] = strconv.Itoa(readiness.StatusCode)
	}
	if readiness.RequestErr {
		metadata["request_error"] = "true"
	}
	return model.Diagnostic{
		ID:       "tempo_readiness",
		Name:     "Tempo runtime readiness",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

func (c *TempoConnector) tags(ctx context.Context, start, end int64) ([]string, error) {
	var response struct {
		TagNames []string `json:"tagNames"`
		Tags     []string `json:"tags"`
	}
	query := url.Values{}
	query.Set("start", strconv.FormatInt(start, 10))
	query.Set("end", strconv.FormatInt(end, 10))
	if err := c.getJSON(ctx, "/api/search/tags?"+query.Encode(), &response); err != nil {
		return nil, err
	}
	if len(response.TagNames) > 0 {
		return response.TagNames, nil
	}
	return response.Tags, nil
}

func (c *TempoConnector) tagValues(ctx context.Context, tag string, start, end int64) ([]string, error) {
	var raw struct {
		TagValues []json.RawMessage `json:"tagValues"`
		Values    []json.RawMessage `json:"values"`
	}
	path := "/api/search/tag/" + url.PathEscape(tag) + "/values"
	query := url.Values{}
	query.Set("start", strconv.FormatInt(start, 10))
	query.Set("end", strconv.FormatInt(end, 10))
	query.Set("limit", strconv.Itoa(c.tagValueLimit+1))
	path += "?" + query.Encode()
	if err := c.getJSON(ctx, path, &raw); err != nil {
		return nil, err
	}
	items := raw.TagValues
	if len(items) == 0 {
		items = raw.Values
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		var value string
		if err := json.Unmarshal(item, &value); err == nil {
			values = append(values, value)
			continue
		}
		var object struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(item, &object); err == nil && object.Value != "" {
			values = append(values, object.Value)
		}
	}
	return values, nil
}

func isTempoServiceNameTag(tag string) bool {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "service.name", "resource.service.name":
		return true
	default:
		return false
	}
}

func (c *TempoConnector) traceServiceResource(serviceName, sourceTag string, now time.Time) model.Resource {
	serviceName = strings.TrimSpace(serviceName)
	resource := c.resource(model.ResourceTypeTraceService, serviceName, "service:"+serviceName, now)
	resource.Labels = map[string]string{model.MetadataService: serviceName}
	resource.Metadata = map[string]string{
		model.MetadataService:       serviceName,
		model.MetadataTraceService:  serviceName,
		model.MetadataTraceTag:      strings.TrimSpace(sourceTag),
		model.MetadataTraceLookback: c.lookback.String(),
	}
	return resource
}

func (c *TempoConnector) getJSON(ctx context.Context, path string, target any) error {
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
		return fmt.Errorf("tempo request %s failed with status %d", path, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func (c *TempoConnector) resource(resourceType model.ResourceType, name string, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", tempoSystem, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     tempoSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *TempoConnector) relationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", tempoSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
