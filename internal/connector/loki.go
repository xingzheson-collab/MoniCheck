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
	lokiSystem         = "loki"
	lokiMaxLabelValues = 200
)

type LokiConnector struct {
	baseURL       string
	client        *http.Client
	detailWorkers int
}

type lokiReadiness struct {
	Available  bool
	Ready      bool
	StatusCode int
	RequestErr bool
}

func NewLokiConnectorWithOptions(baseURL string, options HTTPOptions) (*LokiConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("loki url is empty")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid loki url %q: %w", baseURL, err)
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &LokiConnector{
		baseURL:       baseURL,
		client:        client,
		detailWorkers: defaultConnectorDetailWorkers,
	}, nil
}

func (c *LokiConnector) ID() string {
	return "loki"
}

func (c *LokiConnector) Name() string {
	return "Loki Connector"
}

func (c *LokiConnector) Sync(ctx context.Context) (Snapshot, error) {
	now := time.Now().UTC()
	labels, err := c.labels(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	readiness := c.readiness(ctx)
	labels = uniqueNonEmptyStrings(labels)
	details, workerCount := boundedDetailFetch(ctx, len(labels), c.detailWorkers, func(ctx context.Context, index int) ([]string, error) {
		return c.labelValues(ctx, labels[index])
	})
	resources := make([]model.Resource, 0, len(labels)+1)
	relationships := make([]model.Relationship, 0)
	if readiness.Available {
		runtime := c.resource(model.ResourceTypeInstance, "Loki Runtime", "runtime", now)
		runtime.Metadata = map[string]string{
			model.MetadataLokiRuntime:            "true",
			model.MetadataLokiReadinessAvailable: "true",
			model.MetadataLokiReady:              strconv.FormatBool(readiness.Ready),
		}
		resources = append(resources, runtime)
	}
	failedDetailCount := 0
	for index, label := range labels {
		labelResource := c.resource(model.ResourceTypeLogLabel, label, "label:"+label, now)
		detail := details[index]
		if detail.Err != nil {
			failedDetailCount++
			labelResource.Metadata = map[string]string{
				model.MetadataLogLabel:                label,
				model.MetadataValueDiscoveryAvailable: "false",
			}
			resources = append(resources, labelResource)
			continue
		}
		discoveredValues := privacySafeDiscoveredValues(lokiSystem, label, detail.Value)
		truncated := len(discoveredValues) > lokiMaxLabelValues
		labelResource.Metadata = map[string]string{
			model.MetadataLogLabel:                label,
			model.MetadataLogLabelValueCount:      fmt.Sprintf("%d", len(discoveredValues)),
			model.MetadataValueDiscoveryAvailable: "true",
		}
		if truncated {
			labelResource.Metadata[model.MetadataTruncated] = "true"
		}
		resources = append(resources, labelResource)
		if truncated {
			discoveredValues = discoveredValues[:lokiMaxLabelValues]
		}
		for _, value := range discoveredValues {
			legacyExternalID := "label:" + label + ":value:" + value.raw
			valueResource := c.resource(
				model.ResourceTypeLogLabelValue,
				redactedDiscoveredValueName(label, value.fingerprint),
				legacyExternalID,
				now,
			)
			redactedExternalID := "label:" + label + ":value-fingerprint:" + value.fingerprint
			valueResource.UID = redactedExternalID
			valueResource.Source.ExternalID = redactedExternalID
			valueResource.Metadata = map[string]string{
				model.MetadataLogLabel:         label,
				model.MetadataValueFingerprint: value.fingerprint,
				model.MetadataValueRedacted:    "true",
			}
			if truncated {
				valueResource.Metadata[model.MetadataTruncated] = "true"
			}
			resources = append(resources, valueResource)
			relationships = append(relationships, c.relationship(valueResource.ID, labelResource.ID, model.RelationshipBelongsTo, now))
		}
	}
	diagnostic := detailDiscoveryDiagnostic("loki_label_values", "Loki label value", lokiSystem, "/loki/api/v1/label/{label}/values", len(labels), failedDetailCount)
	addDetailDiscoveryWorkerCount(&diagnostic, workerCount)
	readinessDiagnostic := lokiReadinessDiagnostic(readiness)
	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   []model.Diagnostic{diagnostic, readinessDiagnostic},
		Partial:       failedDetailCount > 0 || !readiness.Available,
	}, nil
}

func (c *LokiConnector) readiness(ctx context.Context) lokiReadiness {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ready", nil)
	if err != nil {
		return lokiReadiness{RequestErr: true}
	}
	response, err := c.client.Do(request)
	if err != nil {
		return lokiReadiness{RequestErr: true}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	switch response.StatusCode {
	case http.StatusOK:
		return lokiReadiness{Available: true, Ready: true, StatusCode: response.StatusCode}
	case http.StatusServiceUnavailable:
		return lokiReadiness{Available: true, Ready: false, StatusCode: response.StatusCode}
	default:
		return lokiReadiness{StatusCode: response.StatusCode}
	}
}

func lokiReadinessDiagnostic(readiness lokiReadiness) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := "Loki readiness discovery completed"
	if readiness.Available && !readiness.Ready {
		status = model.ExecutionStatusWarning
		message = "Loki readiness endpoint reports the configured component is not ready"
	} else if !readiness.Available {
		status = model.ExecutionStatusWarning
		message = "Loki readiness endpoint is unavailable; log label discovery continued"
	}
	metadata := map[string]string{
		"endpoint":  "/ready",
		"optional":  "true",
		"system":    lokiSystem,
		"available": strconv.FormatBool(readiness.Available),
		"scope":     "configured_component",
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
		ID:       "loki_readiness",
		Name:     "Loki runtime readiness",
		Status:   status,
		Message:  message,
		Metadata: metadata,
	}
}

func (c *LokiConnector) labels(ctx context.Context) ([]string, error) {
	var response struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
		Error  string   `json:"error"`
	}
	if err := c.getJSON(ctx, "/loki/api/v1/labels", &response); err != nil {
		return nil, err
	}
	if response.Status != "" && response.Status != "success" {
		if response.Error != "" {
			return nil, fmt.Errorf("loki labels failed: %s", response.Error)
		}
		return nil, fmt.Errorf("loki labels failed with status %q", response.Status)
	}
	return response.Data, nil
}

func (c *LokiConnector) labelValues(ctx context.Context, label string) ([]string, error) {
	var response struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
		Error  string   `json:"error"`
	}
	path := "/loki/api/v1/label/" + url.PathEscape(label) + "/values"
	if err := c.getJSON(ctx, path, &response); err != nil {
		return nil, err
	}
	if response.Status != "" && response.Status != "success" {
		if response.Error != "" {
			return nil, fmt.Errorf("loki label values for %q failed: %s", label, response.Error)
		}
		return nil, fmt.Errorf("loki label values for %q failed with status %q", label, response.Status)
	}
	return response.Data, nil
}

func (c *LokiConnector) getJSON(ctx context.Context, path string, target any) error {
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
		return fmt.Errorf("loki request %s failed with status %d", path, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func (c *LokiConnector) resource(resourceType model.ResourceType, name string, externalID string, now time.Time) model.Resource {
	return model.Resource{
		ID:   model.StableID("resource", lokiSystem, string(resourceType), externalID),
		Type: resourceType,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     lokiSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata:  map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func (c *LokiConnector) relationship(fromID string, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID("relationship", lokiSystem, fromID, toID, string(relationshipType)),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}
