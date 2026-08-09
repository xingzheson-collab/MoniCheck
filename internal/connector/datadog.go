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
	datadogSystem                    = "datadog"
	datadogMonitorPageSize           = 100
	datadogServicePageSize           = 100
	datadogNotificationRulePageSize  = 100
	maxDatadogMonitorCount           = 50000
	maxDatadogServiceDefinitionCount = 10000
	maxDatadogNotificationRuleCount  = 10000
	maxDatadogResponseSize           = 16 << 20
)

type DatadogConnector struct {
	baseURL string
	client  *http.Client
}

type datadogMonitor struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	OverallState string   `json:"overall_state"`
	DraftStatus  string   `json:"draft_status"`
	Priority     *int     `json:"priority"`
	Query        string   `json:"query"`
	Message      string   `json:"message"`
	Tags         []string `json:"tags"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Assets       []struct {
		Category string `json:"category"`
	} `json:"assets"`
	RestrictedRoles []string `json:"restricted_roles"`
	Options         struct {
		NotifyNoData        *bool           `json:"notify_no_data"`
		NoDataTimeframe     *int            `json:"no_data_timeframe"`
		OnMissingData       string          `json:"on_missing_data"`
		RenotifyInterval    *int            `json:"renotify_interval"`
		RenotifyOccurrences *int            `json:"renotify_occurrences"`
		RequireFullWindow   *bool           `json:"require_full_window"`
		Thresholds          json.RawMessage `json:"thresholds"`
	} `json:"options"`
	MatchingDowntimes []json.RawMessage `json:"matching_downtimes"`
}

type datadogServiceDefinitionResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes struct {
			Schema struct {
				DDService   string `json:"dd-service"`
				Team        string `json:"team"`
				Lifecycle   string `json:"lifecycle"`
				Application string `json:"application"`
				Tier        string `json:"tier"`
				Contacts    []struct {
					Type string `json:"type"`
				} `json:"contacts"`
				Links []struct {
					Type string `json:"type"`
				} `json:"links"`
				Integrations map[string]json.RawMessage `json:"integrations"`
			} `json:"schema"`
		} `json:"attributes"`
	} `json:"data"`
}

type datadogNotificationRuleResponse struct {
	Data []datadogNotificationRule `json:"data"`
}

type datadogNotificationRule struct {
	ID         string `json:"id"`
	Attributes struct {
		Name                  string          `json:"name"`
		Filter                json.RawMessage `json:"filter"`
		Recipients            []string        `json:"recipients"`
		ConditionalRecipients json.RawMessage `json:"conditional_recipients"`
	} `json:"attributes"`
}

type datadogNotificationRuleFilter struct {
	Tags  []string `json:"tags"`
	Scope string   `json:"scope"`
}

type datadogConditionalRecipients struct {
	Conditions         []datadogConditionalRecipientCondition `json:"conditions"`
	FallbackRecipients []string                               `json:"fallback_recipients"`
}

type datadogConditionalRecipientCondition struct {
	Scope      string   `json:"scope"`
	Recipients []string `json:"recipients"`
}

func NewDatadogConnectorWithOptions(baseURL string, options HTTPOptions) (*DatadogConnector, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("datadog url is empty")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid datadog url %q", baseURL)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("datadog url must not contain userinfo")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("datadog url must use http or https")
	}
	if options.Timeout <= 0 {
		options.Timeout = 20 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &DatadogConnector{baseURL: baseURL, client: client}, nil
}

func (c *DatadogConnector) ID() string {
	return datadogSystem
}

func (c *DatadogConnector) Name() string {
	return "Datadog Connector"
}

func (c *DatadogConnector) Sync(ctx context.Context) (Snapshot, error) {
	monitors, err := c.fetchMonitors(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	services, serviceTruncated, serviceErr := c.fetchServiceDefinitions(ctx)
	notificationRules, notificationTruncated, notificationErr := c.fetchNotificationRules(ctx)
	now := time.Now().UTC()
	resources := make([]model.Resource, 0, len(monitors)+len(services)+len(notificationRules))
	relationships := make([]model.Relationship, 0, len(monitors)*2)
	serviceIDs := make(map[string]string, len(services))
	notificationMatches := make([]datadogNotificationRuleMatch, 0, len(notificationRules))

	for _, definition := range services {
		resource, ok := c.serviceResource(definition, now)
		if !ok {
			continue
		}
		resources = append(resources, resource)
		serviceIDs[strings.ToLower(resource.Name)] = resource.ID
	}
	for _, rule := range notificationRules {
		match := c.notificationRuleMatch(rule, now)
		resources = append(resources, match.Resource)
		notificationMatches = append(notificationMatches, match)
	}
	for _, monitor := range monitors {
		resource := c.monitorResource(monitor, now)
		matchedNotificationRules := 0
		notificationCoverageUnknown := notificationErr != nil || notificationTruncated
		for _, match := range notificationMatches {
			if !match.HasPotentialCoverage {
				continue
			}
			if !match.FilterSimple {
				notificationCoverageUnknown = true
				continue
			}
			if !datadogTagsMatch(monitor.Tags, match.FilterTags) {
				continue
			}
			configured, evaluable := match.notificationCoverage(monitor.Tags)
			if !evaluable {
				notificationCoverageUnknown = true
				continue
			}
			if !configured {
				continue
			}
			matchedNotificationRules++
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID("relationship", datadogSystem, resource.ID, match.Resource.ID, string(model.RelationshipUses)),
				FromID:    resource.ID,
				ToID:      match.Resource.ID,
				Type:      model.RelationshipUses,
				Metadata:  map[string]string{"derived_from": "notification_rule.filter.tags"},
				CreatedAt: now,
			})
		}
		directNotification := datadogMessageHasRecipient(monitor.Message)
		notificationConfigured := directNotification || matchedNotificationRules > 0
		notificationEvaluable := notificationConfigured || !notificationCoverageUnknown
		resource.Metadata[model.MetadataDatadogDirectNotificationConfigured] = strconv.FormatBool(directNotification)
		resource.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] = strconv.FormatBool(notificationEvaluable)
		resource.Metadata[model.MetadataDatadogNotificationCoverageConfigured] = strconv.FormatBool(notificationConfigured)
		resource.Metadata[model.MetadataDatadogNotificationRuleMatchedCount] = strconv.Itoa(matchedNotificationRules)
		serviceName := strings.TrimSpace(resource.Labels[model.MetadataService])
		if serviceID := serviceIDs[strings.ToLower(serviceName)]; serviceID != "" {
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID("relationship", datadogSystem, resource.ID, serviceID, string(model.RelationshipBelongsTo)),
				FromID:    resource.ID,
				ToID:      serviceID,
				Type:      model.RelationshipBelongsTo,
				Metadata:  map[string]string{"derived_from": "monitor_tag.service"},
				CreatedAt: now,
			})
		}
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	sort.Slice(relationships, func(i, j int) bool { return relationships[i].ID < relationships[j].ID })

	serviceDiagnostic := model.Diagnostic{
		ID:            "datadog_service_definitions",
		Name:          "Datadog service definition discovery",
		Status:        model.ExecutionStatusSucceeded,
		Message:       fmt.Sprintf("Datadog service definition discovery completed for %d services", len(services)),
		ResourceCount: len(services),
		Metadata: map[string]string{
			"endpoint":  "/api/v2/services/definitions",
			"optional":  "true",
			"system":    datadogSystem,
			"truncated": strconv.FormatBool(serviceTruncated),
		},
	}
	if serviceErr != nil || serviceTruncated {
		serviceDiagnostic.Status = model.ExecutionStatusWarning
		if serviceErr != nil {
			serviceDiagnostic.Message = "Datadog service definition discovery is unavailable; monitor discovery continued"
			serviceDiagnostic.Metadata["available"] = "false"
		} else {
			serviceDiagnostic.Message = fmt.Sprintf("Datadog service definition discovery reached the %d-resource safety limit", maxDatadogServiceDefinitionCount)
			serviceDiagnostic.Metadata["available"] = "true"
		}
	} else {
		serviceDiagnostic.Metadata["available"] = "true"
	}
	notificationDiagnostic := model.Diagnostic{
		ID:            "datadog_notification_rules",
		Name:          "Datadog monitor notification rule discovery",
		Status:        model.ExecutionStatusSucceeded,
		Message:       fmt.Sprintf("Datadog notification rule discovery completed for %d rules", len(notificationRules)),
		ResourceCount: len(notificationRules),
		Metadata: map[string]string{
			"endpoint":  "/api/v2/monitor/notification_rule",
			"optional":  "true",
			"system":    datadogSystem,
			"truncated": strconv.FormatBool(notificationTruncated),
		},
	}
	if notificationErr != nil || notificationTruncated {
		notificationDiagnostic.Status = model.ExecutionStatusWarning
		if notificationErr != nil {
			notificationDiagnostic.Message = "Datadog notification rule discovery is unavailable; monitor discovery continued"
			notificationDiagnostic.Metadata["available"] = "false"
		} else {
			notificationDiagnostic.Message = fmt.Sprintf("Datadog notification rule discovery reached the %d-resource safety limit", maxDatadogNotificationRuleCount)
			notificationDiagnostic.Metadata["available"] = "true"
		}
	} else {
		notificationDiagnostic.Metadata["available"] = "true"
	}
	return Snapshot{
		Resources:     resources,
		Relationships: relationships,
		Diagnostics:   []model.Diagnostic{serviceDiagnostic, notificationDiagnostic},
		Partial:       serviceErr != nil || serviceTruncated || notificationErr != nil || notificationTruncated,
	}, nil
}

func (c *DatadogConnector) fetchMonitors(ctx context.Context) ([]datadogMonitor, error) {
	result := make([]datadogMonitor, 0)
	for page := 0; len(result) < maxDatadogMonitorCount; page++ {
		values := url.Values{}
		values.Set("page", strconv.Itoa(page))
		values.Set("page_size", strconv.Itoa(datadogMonitorPageSize))
		values.Set("with_downtimes", "true")
		var batch []datadogMonitor
		if err := c.getJSON(ctx, "/api/v1/monitor?"+values.Encode(), &batch); err != nil {
			return nil, fmt.Errorf("datadog monitor discovery: %w", err)
		}
		result = append(result, batch...)
		if len(batch) < datadogMonitorPageSize {
			return result, nil
		}
	}
	return nil, fmt.Errorf("datadog monitor discovery exceeded the %d-resource safety limit", maxDatadogMonitorCount)
}

func (c *DatadogConnector) fetchServiceDefinitions(ctx context.Context) ([]datadogServiceDefinitionResponseData, bool, error) {
	result := make([]datadogServiceDefinitionResponseData, 0)
	for page := 0; len(result) < maxDatadogServiceDefinitionCount; page++ {
		values := url.Values{}
		values.Set("page[number]", strconv.Itoa(page))
		values.Set("page[size]", strconv.Itoa(datadogServicePageSize))
		var response datadogServiceDefinitionResponse
		if err := c.getJSON(ctx, "/api/v2/services/definitions?"+values.Encode(), &response); err != nil {
			return nil, false, err
		}
		for _, item := range response.Data {
			result = append(result, datadogServiceDefinitionResponseData(item))
		}
		if len(response.Data) < datadogServicePageSize {
			return result, false, nil
		}
	}
	return result, true, nil
}

func (c *DatadogConnector) fetchNotificationRules(ctx context.Context) ([]datadogNotificationRule, bool, error) {
	result := make([]datadogNotificationRule, 0)
	for page := 0; len(result) < maxDatadogNotificationRuleCount; page++ {
		values := url.Values{}
		values.Set("page", strconv.Itoa(page))
		values.Set("per_page", strconv.Itoa(datadogNotificationRulePageSize))
		var response datadogNotificationRuleResponse
		if err := c.getJSON(ctx, "/api/v2/monitor/notification_rule?"+values.Encode(), &response); err != nil {
			return nil, false, err
		}
		result = append(result, response.Data...)
		if len(response.Data) < datadogNotificationRulePageSize {
			return result, false, nil
		}
	}
	return result, true, nil
}

// Alias keeps the mapping helpers readable without exposing API response types.
type datadogServiceDefinitionResponseData = struct {
	ID         string `json:"id"`
	Attributes struct {
		Schema struct {
			DDService   string `json:"dd-service"`
			Team        string `json:"team"`
			Lifecycle   string `json:"lifecycle"`
			Application string `json:"application"`
			Tier        string `json:"tier"`
			Contacts    []struct {
				Type string `json:"type"`
			} `json:"contacts"`
			Links []struct {
				Type string `json:"type"`
			} `json:"links"`
			Integrations map[string]json.RawMessage `json:"integrations"`
		} `json:"schema"`
	} `json:"attributes"`
}

func (c *DatadogConnector) getJSON(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("%s returned status %d", request.URL.Path, response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxDatadogResponseSize))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", request.URL.Path, err)
	}
	return nil
}

func (c *DatadogConnector) monitorResource(monitor datadogMonitor, now time.Time) model.Resource {
	externalID := "monitor:" + strconv.FormatInt(monitor.ID, 10)
	name := strings.TrimSpace(monitor.Name)
	if name == "" {
		name = "Datadog monitor " + strconv.FormatInt(monitor.ID, 10)
	}
	labels := datadogGovernanceTags(monitor.Tags)
	metadata := map[string]string{
		model.MetadataDatadogMonitor:             "true",
		model.MetadataDatadogMonitorType:         strings.TrimSpace(monitor.Type),
		model.MetadataDatadogOverallState:        strings.TrimSpace(monitor.OverallState),
		model.MetadataDatadogDraftStatus:         strings.TrimSpace(monitor.DraftStatus),
		model.MetadataDatadogQueryLength:         strconv.Itoa(len(strings.TrimSpace(monitor.Query))),
		model.MetadataDatadogMessageConfigured:   strconv.FormatBool(strings.TrimSpace(monitor.Message) != ""),
		model.MetadataDatadogRunbookConfigured:   strconv.FormatBool(datadogHasRunbook(monitor)),
		model.MetadataDatadogTagCount:            strconv.Itoa(len(monitor.Tags)),
		model.MetadataDatadogRestrictedRoleCount: strconv.Itoa(len(monitor.RestrictedRoles)),
		model.MetadataDatadogDowntimeCount:       strconv.Itoa(len(monitor.MatchingDowntimes)),
	}
	if service := strings.TrimSpace(labels[model.MetadataService]); service != "" {
		metadata[model.MetadataService] = service
		metadata[model.MetadataDatadogServiceTagDeclared] = "true"
	} else {
		metadata[model.MetadataDatadogServiceTagDeclared] = "false"
	}
	if monitor.Priority != nil {
		metadata[model.MetadataDatadogPriorityDeclared] = "true"
		metadata[model.MetadataDatadogPriority] = strconv.Itoa(*monitor.Priority)
	} else {
		metadata[model.MetadataDatadogPriorityDeclared] = "false"
	}
	if monitor.Options.NotifyNoData != nil {
		metadata[model.MetadataDatadogNotifyNoDataDeclared] = "true"
		metadata[model.MetadataDatadogNotifyNoData] = strconv.FormatBool(*monitor.Options.NotifyNoData)
	} else {
		metadata[model.MetadataDatadogNotifyNoDataDeclared] = "false"
	}
	if monitor.Options.NoDataTimeframe != nil {
		metadata[model.MetadataDatadogNoDataTimeframe] = strconv.Itoa(*monitor.Options.NoDataTimeframe)
	}
	if value := strings.TrimSpace(monitor.Options.OnMissingData); value != "" {
		metadata[model.MetadataDatadogOnMissingData] = value
	}
	noDataEvaluable, noDataConfigured := datadogNoDataNotification(monitor)
	metadata[model.MetadataDatadogNoDataNotificationEvaluable] = strconv.FormatBool(noDataEvaluable)
	metadata[model.MetadataDatadogNoDataNotificationConfigured] = strconv.FormatBool(noDataConfigured)
	recoveryEvaluable, recoveryConfigured := datadogCriticalRecoveryThreshold(monitor)
	metadata[model.MetadataDatadogCriticalRecoveryEvaluable] = strconv.FormatBool(recoveryEvaluable)
	metadata[model.MetadataDatadogCriticalRecoveryConfigured] = strconv.FormatBool(recoveryConfigured)
	if monitor.Options.RenotifyInterval != nil {
		metadata[model.MetadataDatadogRenotifyInterval] = strconv.Itoa(*monitor.Options.RenotifyInterval)
	} else {
		metadata[model.MetadataDatadogRenotifyInterval] = "0"
	}
	if monitor.Options.RenotifyOccurrences != nil {
		metadata[model.MetadataDatadogRenotifyOccurrences] = strconv.Itoa(*monitor.Options.RenotifyOccurrences)
	}
	if monitor.Options.RequireFullWindow != nil {
		metadata[model.MetadataDatadogRequireFullWindow] = strconv.FormatBool(*monitor.Options.RequireFullWindow)
	}
	status := model.ResourceStatusActive
	if strings.EqualFold(strings.TrimSpace(monitor.DraftStatus), "draft") {
		status = model.ResourceStatusDeprecated
		metadata[model.MetadataDisabled] = "true"
	}
	createdAt := datadogTime(monitor.Created, now)
	return model.Resource{
		ID:        model.StableID("resource", datadogSystem, string(model.ResourceTypeAlertRule), externalID),
		Type:      model.ResourceTypeAlertRule,
		Name:      name,
		UID:       externalID,
		Source:    model.SourceInfo{System: datadogSystem, Instance: c.baseURL, ExternalID: externalID},
		Metadata:  metadata,
		Labels:    labels,
		CreatedAt: createdAt,
		UpdatedAt: datadogTime(monitor.Modified, createdAt),
		Status:    status,
	}
}

func datadogCriticalRecoveryThreshold(monitor datadogMonitor) (bool, bool) {
	if !strings.EqualFold(strings.TrimSpace(monitor.Type), "metric alert") {
		return false, false
	}
	raw := strings.TrimSpace(string(monitor.Options.Thresholds))
	if raw == "" || raw == "null" {
		return true, false
	}
	var thresholds map[string]json.RawMessage
	if json.Unmarshal(monitor.Options.Thresholds, &thresholds) != nil || thresholds == nil {
		return false, false
	}
	if value, ok := thresholds["critical_recovery"]; ok {
		if strings.TrimSpace(string(value)) == "null" {
			return true, false
		}
		var threshold float64
		if json.Unmarshal(value, &threshold) != nil {
			return false, false
		}
		return true, true
	}
	if value, ok := thresholds["critical_recovery_query"]; ok {
		var query string
		if json.Unmarshal(value, &query) != nil {
			return false, false
		}
		return true, strings.TrimSpace(query) != ""
	}
	return true, false
}

func datadogNoDataNotification(monitor datadogMonitor) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(monitor.Options.OnMissingData)) {
	case "show_and_notify_no_data":
		return true, true
	case "default", "show_no_data", "resolve":
		return true, false
	case "":
		if monitor.Options.NotifyNoData != nil {
			return true, *monitor.Options.NotifyNoData
		}
	}
	return false, false
}

type datadogNotificationRuleMatch struct {
	Resource              model.Resource
	FilterTags            []string
	FilterSimple          bool
	DirectRecipientCount  int
	ConditionalDeclared   bool
	ConditionalRecipients datadogConditionalRecipients
	ConditionalEvaluable  bool
	HasPotentialCoverage  bool
}

func (c *DatadogConnector) notificationRuleMatch(rule datadogNotificationRule, now time.Time) datadogNotificationRuleMatch {
	var filter datadogNotificationRuleFilter
	filterValid := len(rule.Attributes.Filter) == 0 || json.Unmarshal(rule.Attributes.Filter, &filter) == nil
	conditionalDeclared := datadogRawValueDeclared(rule.Attributes.ConditionalRecipients)
	var conditional datadogConditionalRecipients
	conditionalEvaluable := !conditionalDeclared ||
		json.Unmarshal(rule.Attributes.ConditionalRecipients, &conditional) == nil
	scopeDeclared := strings.TrimSpace(filter.Scope) != ""
	filterSimple := filterValid && !scopeDeclared
	hasConditionalRecipients := false
	if conditionalDeclared && conditionalEvaluable {
		hasConditionalRecipients = len(conditional.FallbackRecipients) > 0
		for _, condition := range conditional.Conditions {
			hasConditionalRecipients = hasConditionalRecipients || len(condition.Recipients) > 0
		}
	}
	name := strings.TrimSpace(rule.Attributes.Name)
	if name == "" {
		name = "Datadog notification rule"
	}
	externalID := "notification-rule:" + model.StableID("datadog-notification-rule", strings.TrimSpace(rule.ID))
	resource := model.Resource{
		ID:   model.StableID("resource", datadogSystem, string(model.ResourceTypeNotificationPolicy), externalID),
		Type: model.ResourceTypeNotificationPolicy,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     datadogSystem,
			Instance:   c.baseURL,
			ExternalID: externalID,
		},
		Metadata: map[string]string{
			model.MetadataDatadogNotificationRule:              "true",
			model.MetadataDatadogNotificationRecipientCount:    strconv.Itoa(len(rule.Attributes.Recipients)),
			model.MetadataDatadogNotificationFilterTagCount:    strconv.Itoa(len(filter.Tags)),
			model.MetadataDatadogNotificationScopeDeclared:     strconv.FormatBool(scopeDeclared),
			model.MetadataDatadogConditionalRecipientsDeclared: strconv.FormatBool(conditionalDeclared),
			model.MetadataDatadogNotificationConditionCount:    strconv.Itoa(len(conditional.Conditions)),
			model.MetadataDatadogNotificationFallbackRecipientCount: strconv.Itoa(
				len(conditional.FallbackRecipients),
			),
		},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
	return datadogNotificationRuleMatch{
		Resource:              resource,
		FilterTags:            append([]string(nil), filter.Tags...),
		FilterSimple:          filterSimple,
		DirectRecipientCount:  len(rule.Attributes.Recipients),
		ConditionalDeclared:   conditionalDeclared,
		ConditionalRecipients: conditional,
		ConditionalEvaluable:  conditionalEvaluable,
		HasPotentialCoverage: len(rule.Attributes.Recipients) > 0 ||
			(conditionalDeclared && (!conditionalEvaluable || hasConditionalRecipients)),
	}
}

func (match datadogNotificationRuleMatch) notificationCoverage(monitorTags []string) (bool, bool) {
	if match.DirectRecipientCount > 0 {
		return true, true
	}
	if !match.ConditionalDeclared {
		return false, true
	}
	if !match.ConditionalEvaluable {
		return false, false
	}
	if len(match.ConditionalRecipients.FallbackRecipients) > 0 {
		return true, true
	}
	for _, condition := range match.ConditionalRecipients.Conditions {
		if len(condition.Recipients) == 0 {
			continue
		}
		scope := strings.TrimSpace(condition.Scope)
		if strings.EqualFold(scope, "transition_type:is_alert") {
			return true, true
		}
		lowerScope := strings.ToLower(scope)
		if strings.HasPrefix(lowerScope, "transition_type:") {
			switch strings.TrimPrefix(lowerScope, "transition_type:") {
			case "is_warn", "is_warning", "is_no_data", "is_recovery", "is_alert_recovery",
				"is_warning_recovery", "is_no_data_recovery":
				continue
			default:
				return false, false
			}
		}
		if !datadogConditionalTagScope(scope) {
			return false, false
		}
		if datadogTagsMatch(monitorTags, []string{scope}) {
			return true, true
		}
	}
	return false, true
}

func datadogConditionalTagScope(scope string) bool {
	if strings.ContainsAny(scope, " \t\r\n()") {
		return false
	}
	key, value, ok := strings.Cut(scope, ":")
	return ok && strings.TrimSpace(key) != "" && strings.TrimSpace(value) != ""
}

func datadogRawValueDeclared(value json.RawMessage) bool {
	normalized := strings.TrimSpace(string(value))
	return normalized != "" && normalized != "null" && normalized != "{}" && normalized != "[]"
}

func datadogMessageHasRecipient(message string) bool {
	for _, field := range strings.Fields(message) {
		field = strings.TrimLeft(field, "([{")
		if strings.HasPrefix(field, "@") && len(field) > 1 {
			return true
		}
	}
	return false
}

func datadogTagsMatch(monitorTags, filterTags []string) bool {
	available := make(map[string]bool, len(monitorTags))
	for _, tag := range monitorTags {
		available[strings.ToLower(strings.TrimSpace(tag))] = true
	}
	for _, tag := range filterTags {
		if !available[strings.ToLower(strings.TrimSpace(tag))] {
			return false
		}
	}
	return true
}

func (c *DatadogConnector) serviceResource(item datadogServiceDefinitionResponseData, now time.Time) (model.Resource, bool) {
	schema := item.Attributes.Schema
	name := strings.TrimSpace(schema.DDService)
	if name == "" {
		name = strings.TrimSpace(item.ID)
	}
	if name == "" {
		return model.Resource{}, false
	}
	externalID := "service:" + strings.TrimSpace(item.ID)
	if strings.TrimSpace(item.ID) == "" {
		externalID = "service:" + strings.ToLower(name)
	}
	labels := map[string]string{model.MetadataService: name}
	metadata := map[string]string{
		model.MetadataService:                  name,
		model.MetadataDatadogServiceDefinition: "true",
		model.MetadataDatadogTeamDeclared:      strconv.FormatBool(strings.TrimSpace(schema.Team) != ""),
		model.MetadataDatadogContactCount:      strconv.Itoa(len(schema.Contacts)),
		model.MetadataDatadogLinkCount:         strconv.Itoa(len(schema.Links)),
		model.MetadataDatadogIntegrationCount:  strconv.Itoa(len(schema.Integrations)),
		model.MetadataDatadogRunbookConfigured: strconv.FormatBool(datadogServiceHasLink(schema.Links, "runbook")),
	}
	setDatadogMetadata(metadata, model.MetadataDatadogLifecycle, schema.Lifecycle)
	setDatadogMetadata(metadata, model.MetadataDatadogApplication, schema.Application)
	setDatadogMetadata(metadata, model.MetadataDatadogTier, schema.Tier)
	if team := strings.TrimSpace(schema.Team); team != "" {
		labels["team"] = team
		metadata["team"] = team
	}
	return model.Resource{
		ID:        model.StableID("resource", datadogSystem, string(model.ResourceTypeService), externalID),
		Type:      model.ResourceTypeService,
		Name:      name,
		UID:       externalID,
		Source:    model.SourceInfo{System: datadogSystem, Instance: c.baseURL, ExternalID: externalID},
		Metadata:  metadata,
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}, true
}

func datadogGovernanceTags(tags []string) map[string]string {
	allowed := map[string]bool{
		model.MetadataService: true,
		"team":                true, "owner": true, "env": true, "environment": true,
		"application": true, "app": true, "component": true, "severity": true,
	}
	result := make(map[string]string)
	for _, tag := range tags {
		key, value, ok := strings.Cut(tag, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || !allowed[key] || key == "" || value == "" {
			continue
		}
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}
	return result
}

func datadogHasRunbook(monitor datadogMonitor) bool {
	for _, asset := range monitor.Assets {
		if strings.EqualFold(strings.TrimSpace(asset.Category), "runbook") {
			return true
		}
	}
	return false
}

func datadogServiceHasLink(links []struct {
	Type string `json:"type"`
}, target string) bool {
	for _, link := range links {
		if strings.EqualFold(strings.TrimSpace(link.Type), target) {
			return true
		}
	}
	return false
}

func setDatadogMetadata(metadata map[string]string, key string, value string) {
	if value = strings.TrimSpace(value); value != "" {
		metadata[key] = value
	}
}

func datadogTime(value string, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
		return parsed.UTC()
	}
	return fallback
}
