package connector

import (
	"bytes"
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
	pyroscopeSystem         = "pyroscope"
	pyroscopeMaxLabelValues = 200
)

type PyroscopeConnector struct {
	baseURL       string
	client        *http.Client
	lookback      time.Duration
	detailWorkers int
}

type pyroscopeProfileType struct {
	ID         string `json:"ID"`
	Name       string `json:"name"`
	SampleType string `json:"sampleType"`
	SampleUnit string `json:"sampleUnit"`
	PeriodType string `json:"periodType"`
	PeriodUnit string `json:"periodUnit"`
}

type pyroscopeReadiness struct {
	Available  bool
	Ready      bool
	StatusCode int
	RequestErr bool
}

func NewPyroscopeConnectorWithOptions(baseURL string, lookback time.Duration, options HTTPOptions) (*PyroscopeConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("pyroscope url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid pyroscope url %q: %w", baseURL, err)
	}
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &PyroscopeConnector{
		baseURL:       baseURL,
		client:        client,
		lookback:      lookback,
		detailWorkers: defaultConnectorDetailWorkers,
	}, nil
}

func (c *PyroscopeConnector) ID() string {
	return pyroscopeSystem
}

func (c *PyroscopeConnector) Name() string {
	return "Pyroscope Connector"
}

func (c *PyroscopeConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	start := now.Add(-c.lookback).UnixMilli()
	end := now.UnixMilli()
	labelNames, err := c.labelNames(ctx, start, end)
	if err != nil {
		return Snapshot{}, err
	}
	profileTypes, err := c.profileTypes(ctx, start, end)
	if err != nil {
		return Snapshot{}, err
	}
	readiness := c.readiness(ctx)

	labelNames = uniqueNonEmptyStrings(labelNames)
	details, workerCount := boundedDetailFetch(ctx, len(labelNames), c.detailWorkers, func(ctx context.Context, index int) ([]string, error) {
		return c.labelValues(ctx, labelNames[index], start, end)
	})
	resources := make([]model.Resource, 0, len(labelNames)+len(profileTypes)+1)
	relationships := make([]model.Relationship, 0)
	if readiness.Available {
		runtime := c.resource(model.ResourceTypeInstance, "Pyroscope Runtime", "runtime", now)
		runtime.Metadata = map[string]string{
			model.MetadataPyroscopeRuntime:            "true",
			model.MetadataPyroscopeReadinessAvailable: "true",
			model.MetadataPyroscopeReady:              strconv.FormatBool(readiness.Ready),
		}
		resources = append(resources, runtime)
	}
	profileTypeIDs := make(map[string]struct{}, len(profileTypes))
	for _, profileType := range profileTypes {
		if resource, ok := c.profileTypeResource(profileType, now); ok {
			if _, exists := profileTypeIDs[resource.ID]; exists {
				continue
			}
			profileTypeIDs[resource.ID] = struct{}{}
			resources = append(resources, resource)
		}
	}

	failedDetailCount := 0
	profileServiceIDs := make(map[string]struct{})
	for index, labelName := range labelNames {
		labelResource := c.resource(model.ResourceTypeProfileLabel, labelName, "label:"+labelName, now)
		labelResource.Metadata = map[string]string{model.MetadataProfileLabel: labelName}
		detail := details[index]
		if detail.Err != nil {
			failedDetailCount++
			labelResource.Metadata[model.MetadataValueDiscoveryAvailable] = "false"
			resources = append(resources, labelResource)
			continue
		}
		values := privacySafeDiscoveredValues(pyroscopeSystem, labelName, detail.Value)
		truncated := len(values) > pyroscopeMaxLabelValues
		labelResource.Metadata[model.MetadataValueDiscoveryAvailable] = "true"
		labelResource.Metadata[model.MetadataProfileLabelValueCount] = fmt.Sprintf("%d", len(values))
		if truncated {
			labelResource.Metadata[model.MetadataTruncated] = "true"
		}
		resources = append(resources, labelResource)

		sampledValues := values
		if truncated {
			sampledValues = values[:pyroscopeMaxLabelValues]
		}
		for _, value := range sampledValues {
			legacyExternalID := "label:" + labelName + ":value:" + value.raw
			valueResource := c.resource(
				model.ResourceTypeProfileLabelValue,
				redactedDiscoveredValueName(labelName, value.fingerprint),
				legacyExternalID,
				now,
			)
			redactedExternalID := "label:" + labelName + ":value-fingerprint:" + value.fingerprint
			valueResource.UID = redactedExternalID
			valueResource.Source.ExternalID = redactedExternalID
			valueResource.Metadata = map[string]string{
				model.MetadataProfileLabel:     labelName,
				model.MetadataValueFingerprint: value.fingerprint,
				model.MetadataValueRedacted:    "true",
			}
			if truncated {
				valueResource.Metadata[model.MetadataTruncated] = "true"
			}
			resources = append(resources, valueResource)
			relationships = append(relationships, c.relationship(valueResource.ID, labelResource.ID, model.RelationshipBelongsTo, now))
		}

		if labelName == "service_name" || labelName == "service.name" {
			for _, serviceName := range uniqueNonEmptyStrings(detail.Value) {
				serviceResource := c.resource(model.ResourceTypeProfileService, serviceName, "service:"+serviceName, now)
				if _, exists := profileServiceIDs[serviceResource.ID]; exists {
					continue
				}
				profileServiceIDs[serviceResource.ID] = struct{}{}
				serviceResource.Labels = map[string]string{model.MetadataService: serviceName}
				serviceResource.Metadata = map[string]string{
					model.MetadataService:        serviceName,
					model.MetadataProfileService: serviceName,
				}
				resources = append(resources, serviceResource)
			}
		}
	}

	diagnostic := detailDiscoveryDiagnostic(
		"pyroscope_label_values",
		"Pyroscope label value",
		pyroscopeSystem,
		"/querier.v1.QuerierService/LabelValues",
		len(labelNames),
		failedDetailCount,
	)
	addDetailDiscoveryWorkerCount(&diagnostic, workerCount)
	readinessDiagnostic := pyroscopeReadinessDiagnostic(readiness)
	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   []model.Diagnostic{diagnostic, readinessDiagnostic},
		Partial:       failedDetailCount > 0 || !readiness.Available,
	}, nil
}

func (c *PyroscopeConnector) readiness(ctx context.Context) pyroscopeReadiness {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ready", nil)
	if err != nil {
		return pyroscopeReadiness{RequestErr: true}
	}
	response, err := c.client.Do(request)
	if err != nil {
		return pyroscopeReadiness{RequestErr: true}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	switch {
	case response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices:
		return pyroscopeReadiness{Available: true, Ready: true, StatusCode: response.StatusCode}
	case response.StatusCode == http.StatusServiceUnavailable:
		return pyroscopeReadiness{Available: true, Ready: false, StatusCode: response.StatusCode}
	default:
		return pyroscopeReadiness{StatusCode: response.StatusCode}
	}
}

func pyroscopeReadinessDiagnostic(readiness pyroscopeReadiness) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "Pyroscope readiness discovery completed"
	if readiness.Available && !readiness.Ready {
		status = model.ExecutionStatusWarning
		message = "Pyroscope readiness endpoint reports the runtime is not ready"
	} else if !readiness.Available {
		status = model.ExecutionStatusWarning
		message = "Pyroscope readiness endpoint is unavailable; profile catalog discovery continued"
	}
	metadata := map[string]string{
		"endpoint":  "/ready",
		"optional":  "true",
		"system":    pyroscopeSystem,
		"available": strconv.FormatBool(readiness.Available),
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
		ID:       "pyroscope_readiness",
		Name:     "Pyroscope runtime readiness",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

func (c *PyroscopeConnector) labelNames(ctx context.Context, start, end int64) ([]string, error) {
	var response struct {
		Names []string `json:"names"`
	}
	if err := c.postJSON(ctx, "/querier.v1.QuerierService/LabelNames", map[string]any{"start": start, "end": end}, &response); err != nil {
		return nil, fmt.Errorf("pyroscope label names: %w", err)
	}
	return response.Names, nil
}

func (c *PyroscopeConnector) labelValues(ctx context.Context, name string, start, end int64) ([]string, error) {
	var response struct {
		Names []string `json:"names"`
	}
	body := map[string]any{"name": name, "start": start, "end": end}
	if err := c.postJSON(ctx, "/querier.v1.QuerierService/LabelValues", body, &response); err != nil {
		return nil, fmt.Errorf("pyroscope label values for %q: %w", name, err)
	}
	return response.Names, nil
}

func (c *PyroscopeConnector) profileTypes(ctx context.Context, start, end int64) ([]pyroscopeProfileType, error) {
	var response struct {
		ProfileTypes []pyroscopeProfileType `json:"profileTypes"`
	}
	if err := c.postJSON(ctx, "/querier.v1.QuerierService/ProfileTypes", map[string]any{"start": start, "end": end}, &response); err != nil {
		return nil, fmt.Errorf("pyroscope profile types: %w", err)
	}
	return response.ProfileTypes, nil
}

func (c *PyroscopeConnector) postJSON(ctx context.Context, path string, body any, target any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request = markRequestIdempotent(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("request %s failed with status %d", path, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func (c *PyroscopeConnector) profileTypeResource(profileType pyroscopeProfileType, now time.Time) (model.Resource, bool) {
	id := strings.TrimSpace(profileType.ID)
	if id == "" {
		id = strings.TrimSpace(profileType.Name)
	}
	if id == "" {
		return model.Resource{}, false
	}
	name := strings.TrimSpace(profileType.Name)
	if name == "" {
		name = id
	}
	resource := c.resource(model.ResourceTypeProfileType, name, "profile-type:"+id, now)
	resource.Metadata = map[string]string{model.MetadataProfileType: id}
	addNonEmptyMetadata(resource.Metadata, model.MetadataProfileSampleType, profileType.SampleType)
	addNonEmptyMetadata(resource.Metadata, model.MetadataProfileSampleUnit, profileType.SampleUnit)
	addNonEmptyMetadata(resource.Metadata, model.MetadataProfilePeriodType, profileType.PeriodType)
	addNonEmptyMetadata(resource.Metadata, model.MetadataProfilePeriodUnit, profileType.PeriodUnit)
	return resource, true
}

func addNonEmptyMetadata(metadata map[string]string, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		metadata[key] = value
	}
}

func (c *PyroscopeConnector) resource(resourceType model.ResourceType, name, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", pyroscopeSystem, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     pyroscopeSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *PyroscopeConnector) relationship(fromID, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", pyroscopeSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
