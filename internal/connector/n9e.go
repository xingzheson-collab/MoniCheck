package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
)

const (
	n9eSystem              = "n9e"
	n9eDefaultRulePath     = "/api/n9e/busi-groups/alert-rules"
	n9eDatasourceBriefPath = "/api/n9e/datasource/brief"
	n9eCurrentEventsPath   = "/api/n9e/alert-cur-events/list"
	n9eAlertMutesPath      = "/api/n9e/busi-groups/alert-mutes"
	n9eNotifyRulesPath     = "/api/n9e/notify-rules"
	n9eBusinessGroupsPath  = "/api/n9e/busi-groups?all=true&limit=10000"
	n9eAlertSubscribesPath = "/api/n9e/busi-groups/alert-subscribes"
	n9eHistoryEventsPath   = "/api/n9e/alert-his-events/list"
	n9eEventPageSize       = 1000
	n9eEventLimit          = 50000
	n9eHistoryWindowHours  = 24
	n9eHistoryEventLimit   = 10000
)

type N9EConnector struct {
	baseURL            string
	apiKey             string
	rulePath           string
	historyWindowHours int
	historyEventLimit  int
	client             *http.Client
}

func NewN9EConnector(baseURL string, apiKey string, rulePath string) (*N9EConnector, error) {
	return NewN9EConnectorWithOptions(baseURL, rulePath, HTTPOptions{BearerToken: apiKey, APIKey: apiKey, Timeout: 10 * time.Second})
}

func NewN9EConnectorWithOptions(baseURL string, rulePath string, options HTTPOptions) (*N9EConnector, error) {
	return NewN9EConnectorWithGovernanceOptions(baseURL, rulePath, n9eHistoryWindowHours, n9eHistoryEventLimit, options)
}

func NewN9EConnectorWithGovernanceOptions(baseURL string, rulePath string, historyWindowHours int, historyEventLimit int, options HTTPOptions) (*N9EConnector, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid n9e url: %s", baseURL)
	}
	if rulePath == "" {
		rulePath = n9eDefaultRulePath
	}
	if !strings.HasPrefix(rulePath, "/") {
		rulePath = "/" + rulePath
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if historyWindowHours <= 0 {
		historyWindowHours = n9eHistoryWindowHours
	}
	if historyEventLimit <= 0 {
		historyEventLimit = n9eHistoryEventLimit
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &N9EConnector{
		baseURL:            parsed.String(),
		apiKey:             strings.TrimSpace(options.BearerToken),
		rulePath:           rulePath,
		historyWindowHours: historyWindowHours,
		historyEventLimit:  historyEventLimit,
		client:             client,
	}, nil
}

func (c *N9EConnector) ID() string {
	return "n9e"
}

func (c *N9EConnector) Name() string {
	return "N9E Connector"
}

func (c *N9EConnector) Sync(ctx context.Context) (Snapshot, error) {
	payload, statusCode, err := c.fetchPayload(ctx, c.rulePath)
	if err != nil {
		return Snapshot{}, err
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return Snapshot{}, fmt.Errorf("n9e %s returned status %d", c.rulePath, statusCode)
	}

	diagnostics := make([]model.Diagnostic, 0, 7)
	datasourcePayload, diagnostic := c.fetchOptionalPayload(ctx, n9eDatasourceBriefPath, "n9e_datasource_catalog", "N9E datasource catalog")
	diagnostics = append(diagnostics, diagnostic)
	eventPayload, eventOK := c.fetchCurrentEvents(ctx)
	diagnostics = append(diagnostics, n9eOptionalDiscoveryDiagnostic("n9e_current_alerts", "N9E current alerts", n9eCurrentEventsPath, eventOK))
	mutePayload, diagnostic := c.fetchOptionalPayload(ctx, n9eAlertMutesPath, "n9e_alert_mutes", "N9E alert mutes")
	diagnostics = append(diagnostics, diagnostic)
	notifyPayload, diagnostic := c.fetchOptionalPayload(ctx, n9eNotifyRulesPath, "n9e_notification_rules", "N9E notification rules")
	diagnostics = append(diagnostics, diagnostic)
	businessGroupPayload, diagnostic := c.fetchOptionalPayload(ctx, n9eBusinessGroupsPath, "n9e_business_groups", "N9E business groups")
	diagnostics = append(diagnostics, diagnostic)
	subscribePayload, diagnostic := c.fetchOptionalPayload(ctx, n9eAlertSubscribesPath, "n9e_alert_subscriptions", "N9E alert subscriptions")
	diagnostics = append(diagnostics, diagnostic)
	historyPayload, historyOK := c.fetchHistoricalEvents(ctx)
	diagnostics = append(diagnostics, n9eOptionalDiscoveryDiagnostic("n9e_historical_alerts", "N9E historical alerts", n9eHistoryEventsPath, historyOK))
	snapshot, err := n9eSnapshotFromGovernancePayloads(payload, datasourcePayload, eventPayload, mutePayload, notifyPayload, businessGroupPayload, subscribePayload, historyPayload, c.baseURL, time.Now().UTC())
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Diagnostics = diagnostics
	for _, diagnostic := range diagnostics {
		if diagnostic.Status == model.ExecutionStatusWarning || diagnostic.Status == model.ExecutionStatusFailed {
			snapshot.Partial = true
			break
		}
	}
	return snapshot, nil
}

func (c *N9EConnector) fetchOptionalPayload(ctx context.Context, path string, id string, name string) (any, model.Diagnostic) {
	payload, statusCode, err := c.fetchPayload(ctx, path)
	if err != nil {
		return nil, n9eOptionalDiscoveryDiagnostic(id, name, path, false)
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		diagnostic := n9eOptionalDiscoveryDiagnostic(id, name, path, false)
		diagnostic.Metadata["http_status"] = strconv.Itoa(statusCode)
		return nil, diagnostic
	}
	return payload, n9eOptionalDiscoveryDiagnostic(id, name, path, true)
}

func n9eOptionalDiscoveryDiagnostic(id string, name string, path string, succeeded bool) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := name + " discovery completed"
	if !succeeded {
		status = model.ExecutionStatusWarning
		message = name + " endpoint is unavailable; core rule discovery continued"
	}
	return model.Diagnostic{
		ID:      id,
		Name:    name,
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"endpoint": path,
			"optional": "true",
		},
	}
}

func (c *N9EConnector) fetchCurrentEvents(ctx context.Context) (any, bool) {
	rows := make([]any, 0)
	total := 0
	for page := 1; len(rows) < n9eEventLimit; page++ {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(n9eEventPageSize))
		query.Set("p", strconv.Itoa(page))
		payload, statusCode, err := c.fetchPayload(ctx, n9eCurrentEventsPath+"?"+query.Encode())
		if err != nil || statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
			return nil, false
		}
		pageRows := extractObjectRows(payload)
		for _, row := range pageRows {
			rows = append(rows, row)
			if len(rows) == n9eEventLimit {
				break
			}
		}
		if page == 1 {
			total = n9ePayloadTotal(payload)
		}
		if len(pageRows) == 0 || (total > 0 && len(rows) >= total) || (total == 0 && len(pageRows) < n9eEventPageSize) {
			break
		}
	}
	truncated := total > len(rows) || (total == 0 && len(rows) == n9eEventLimit)
	return map[string]any{"list": rows, "total": total, "retained_count": len(rows), "truncated": truncated}, true
}

func (c *N9EConnector) fetchHistoricalEvents(ctx context.Context) (any, bool) {
	rows := make([]any, 0)
	total := 0
	for page := 1; len(rows) < c.historyEventLimit; page++ {
		pageSize := n9eEventPageSize
		if remaining := c.historyEventLimit - len(rows); remaining < pageSize {
			pageSize = remaining
		}
		query := url.Values{}
		query.Set("hours", strconv.Itoa(c.historyWindowHours))
		query.Set("limit", strconv.Itoa(pageSize))
		query.Set("p", strconv.Itoa(page))
		payload, statusCode, err := c.fetchPayload(ctx, n9eHistoryEventsPath+"?"+query.Encode())
		if err != nil || statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
			return nil, false
		}
		pageRows := extractObjectRows(payload)
		if page == 1 {
			total = n9ePayloadTotal(payload)
		}
		remaining := c.historyEventLimit - len(rows)
		if len(pageRows) > remaining {
			pageRows = pageRows[:remaining]
		}
		for _, row := range pageRows {
			rows = append(rows, row)
		}
		if len(pageRows) < pageSize || (total > 0 && len(rows) >= total) {
			break
		}
	}
	truncated := total > len(rows) || (total == 0 && len(rows) == c.historyEventLimit)
	return map[string]any{"list": rows, "total": total, "window_hours": c.historyWindowHours, "retained_count": len(rows), "truncated": truncated}, true
}

func (c *N9EConnector) fetchPayload(ctx context.Context, path string) (any, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, resp.StatusCode, nil
	}

	var payload any
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, resp.StatusCode, err
	}
	return payload, resp.StatusCode, nil
}

func n9eSnapshotFromPayload(payload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromPayloads(payload, nil, instance, now)
}

func n9eSnapshotFromPayloads(payload any, datasourcePayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromPayloadsAndEvents(payload, datasourcePayload, nil, instance, now)
}

func n9eSnapshotFromPayloadsAndEvents(payload any, datasourcePayload any, eventPayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromPayloadsEventsAndMutes(payload, datasourcePayload, eventPayload, nil, instance, now)
}

func n9eSnapshotFromPayloadsEventsAndMutes(payload any, datasourcePayload any, eventPayload any, mutePayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromPayloadsEventsMutesAndNotifications(payload, datasourcePayload, eventPayload, mutePayload, nil, instance, now)
}

func n9eSnapshotFromPayloadsEventsMutesAndNotifications(payload any, datasourcePayload any, eventPayload any, mutePayload any, notifyPayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromAllPayloads(payload, datasourcePayload, eventPayload, mutePayload, notifyPayload, nil, instance, now)
}

func n9eSnapshotFromAllPayloads(payload any, datasourcePayload any, eventPayload any, mutePayload any, notifyPayload any, businessGroupPayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromCompletePayloads(payload, datasourcePayload, eventPayload, mutePayload, notifyPayload, businessGroupPayload, nil, instance, now)
}

func n9eSnapshotFromCompletePayloads(payload any, datasourcePayload any, eventPayload any, mutePayload any, notifyPayload any, businessGroupPayload any, subscribePayload any, instance string, now time.Time) (Snapshot, error) {
	return n9eSnapshotFromGovernancePayloads(payload, datasourcePayload, eventPayload, mutePayload, notifyPayload, businessGroupPayload, subscribePayload, nil, instance, now)
}

func n9eSnapshotFromGovernancePayloads(payload any, datasourcePayload any, eventPayload any, mutePayload any, notifyPayload any, businessGroupPayload any, subscribePayload any, historyPayload any, instance string, now time.Time) (Snapshot, error) {
	rows := extractObjectRows(payload)
	datasources := n9eDatasourceCatalog(datasourcePayload, instance, now)
	resources := make([]model.Resource, 0, len(rows)+len(datasources)+1)
	relationships := make([]model.Relationship, 0)
	metrics := make(map[string]model.Resource)
	resources = append(resources, n9eRuntimeCoverageResource(rows, eventPayload, historyPayload, instance, now))
	for _, datasource := range datasources {
		resources = append(resources, datasource)
	}

	for _, row := range rows {
		rule, ok := n9eRuleResource(row, instance, now)
		if !ok {
			continue
		}
		resources = append(resources, rule)

		for _, datasource := range n9eDatasourceResources(row, instance, now) {
			if discovered, exists := datasources[datasource.ID]; exists {
				datasource = discovered
			}
			if _, exists := datasources[datasource.ID]; !exists {
				datasources[datasource.ID] = datasource
				resources = append(resources, datasource)
			}
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID(rule.ID, string(model.RelationshipUses), datasource.ID),
				FromID:    rule.ID,
				ToID:      datasource.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			})
		}

		var outputMetric model.Resource
		var hasOutputMetric bool
		if rule.Type == model.ResourceTypeRecordingRule {
			outputName := strings.TrimSpace(rule.Metadata[model.MetadataRecordingRuleOutput])
			if outputName != "" {
				metric, exists := metrics[outputName]
				if !exists {
					metric = n9eResource(model.ResourceTypeMetric, outputName, instance, "metric:"+outputName, now)
					metrics[outputName] = metric
					resources = append(resources, metric)
				}
				outputMetric = metric
				hasOutputMetric = true
				relationships = append(relationships, model.Relationship{
					ID:        model.StableID(rule.ID, string(model.RelationshipProduces), metric.ID),
					FromID:    rule.ID,
					ToID:      metric.ID,
					Type:      model.RelationshipProduces,
					CreatedAt: now,
				})
			}
		}

		for _, metricName := range ExtractPromQLMetricNames(rule.Metadata[model.MetadataPromQL]) {
			metric, exists := metrics[metricName]
			if !exists {
				metric = n9eResource(model.ResourceTypeMetric, metricName, instance, "metric:"+metricName, now)
				metrics[metricName] = metric
				resources = append(resources, metric)
			}
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID(rule.ID, string(model.RelationshipUses), metric.ID),
				FromID:    rule.ID,
				ToID:      metric.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			})
			if hasOutputMetric && metric.ID != outputMetric.ID {
				relationships = append(relationships, model.Relationship{
					ID:     model.StableID(metric.ID, string(model.RelationshipProduces), outputMetric.ID),
					FromID: metric.ID,
					ToID:   outputMetric.ID,
					Type:   model.RelationshipProduces,
					Metadata: map[string]string{
						"via_rule_id":   rule.ID,
						"via_rule_name": rule.Name,
					},
					CreatedAt: now,
				})
			}
		}
	}
	existingResources := make(map[string]int, len(resources))
	for index, resource := range resources {
		existingResources[resource.ID] = index
	}
	for _, row := range extractObjectRows(eventPayload) {
		alert, rule, relationship, ok := n9eCurrentEventResource(row, instance, now)
		if !ok {
			continue
		}
		if _, exists := existingResources[alert.ID]; !exists {
			resources = append(resources, alert)
			existingResources[alert.ID] = len(resources) - 1
		}
		if index, exists := existingResources[rule.ID]; exists {
			for key, value := range rule.Labels {
				if resources[index].Labels[key] == "" {
					resources[index].Labels[key] = value
				}
			}
			annotateSLORuleMetadata(&resources[index])
		} else {
			annotateSLORuleMetadata(&rule)
			resources = append(resources, rule)
			existingResources[rule.ID] = len(resources) - 1
		}
		relationships = append(relationships, relationship)
	}
	for _, row := range extractObjectRows(mutePayload) {
		silence, datasourceIDs, ok := n9eAlertMuteResource(row, instance, now)
		if !ok {
			continue
		}
		if _, exists := existingResources[silence.ID]; !exists {
			resources = append(resources, silence)
			existingResources[silence.ID] = len(resources) - 1
		}
		for _, datasourceID := range datasourceIDs {
			if datasourceID == "0" {
				continue
			}
			datasource := n9eResource(model.ResourceTypeDatasource, datasourceID, instance, "datasource:"+datasourceID, now)
			if discovered, exists := datasources[datasource.ID]; exists {
				datasource = discovered
			} else if _, exists := existingResources[datasource.ID]; !exists {
				datasource.Metadata[model.MetadataDatasourceUID] = datasourceID
				datasource.Metadata[model.MetadataDatasourceType] = "prometheus"
				resources = append(resources, datasource)
				existingResources[datasource.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID(silence.ID, string(model.RelationshipUses), datasource.ID),
				FromID:    silence.ID,
				ToID:      datasource.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			})
		}
	}
	for _, row := range extractObjectRows(notifyPayload) {
		policy, receivers, ok := n9eNotificationPolicyResource(row, instance, now)
		if !ok {
			continue
		}
		if _, exists := existingResources[policy.ID]; !exists {
			resources = append(resources, policy)
			existingResources[policy.ID] = len(resources) - 1
		}
		for _, receiver := range receivers {
			if index, exists := existingResources[receiver.ID]; exists {
				existingCount, _ := strconv.Atoi(resources[index].Metadata[model.MetadataReceiverRouteCount])
				resources[index].Metadata[model.MetadataReceiverRouteCount] = strconv.Itoa(existingCount + 1)
			} else {
				resources = append(resources, receiver)
				existingResources[receiver.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID(policy.ID, string(model.RelationshipUses), receiver.ID),
				FromID:    policy.ID,
				ToID:      receiver.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			})
		}
	}
	for _, row := range extractObjectRows(subscribePayload) {
		subscription, receivers, ruleIDs, datasourceIDs, notifyRuleIDs, ok := n9eAlertSubscriptionResource(row, instance, now)
		if !ok {
			continue
		}
		if _, exists := existingResources[subscription.ID]; !exists {
			resources = append(resources, subscription)
			existingResources[subscription.ID] = len(resources) - 1
		}
		for _, ruleID := range ruleIDs {
			rule := n9eResource(model.ResourceTypeAlertRule, "rule-"+ruleID, instance, "rule:"+ruleID, now)
			if _, exists := existingResources[rule.ID]; !exists {
				rule.Status = model.ResourceStatusOrphan
				rule.Metadata["declared"] = "false"
				resources = append(resources, rule)
				existingResources[rule.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{ID: model.StableID(rule.ID, string(model.RelationshipUses), subscription.ID), FromID: rule.ID, ToID: subscription.ID, Type: model.RelationshipUses, CreatedAt: now})
		}
		for _, datasourceID := range datasourceIDs {
			if datasourceID == "0" {
				continue
			}
			datasource := n9eResource(model.ResourceTypeDatasource, datasourceID, instance, "datasource:"+datasourceID, now)
			if discovered, exists := datasources[datasource.ID]; exists {
				datasource = discovered
			} else if _, exists := existingResources[datasource.ID]; !exists {
				datasource.Metadata[model.MetadataDatasourceUID] = datasourceID
				datasource.Metadata[model.MetadataDatasourceType] = "prometheus"
				resources = append(resources, datasource)
				existingResources[datasource.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{ID: model.StableID(subscription.ID, string(model.RelationshipUses), datasource.ID), FromID: subscription.ID, ToID: datasource.ID, Type: model.RelationshipUses, CreatedAt: now})
		}
		for _, notifyRuleID := range notifyRuleIDs {
			policy := n9eResource(model.ResourceTypeNotificationPolicy, "notify-rule-"+notifyRuleID, instance, "notification-policy:"+notifyRuleID, now)
			if _, exists := existingResources[policy.ID]; !exists {
				policy.Metadata["declared"] = "false"
				resources = append(resources, policy)
				existingResources[policy.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{ID: model.StableID(subscription.ID, string(model.RelationshipUses), policy.ID), FromID: subscription.ID, ToID: policy.ID, Type: model.RelationshipUses, CreatedAt: now})
		}
		for _, receiver := range receivers {
			if _, exists := existingResources[receiver.ID]; !exists {
				resources = append(resources, receiver)
				existingResources[receiver.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{ID: model.StableID(subscription.ID, string(model.RelationshipUses), receiver.ID), FromID: subscription.ID, ToID: receiver.ID, Type: model.RelationshipUses, CreatedAt: now})
		}
	}
	for index := range resources {
		resource := resources[index]
		if resource.Type != model.ResourceTypeAlertRule && resource.Type != model.ResourceTypeRecordingRule {
			continue
		}
		for _, policyID := range strings.Split(resource.Metadata["notify_rule_ids"], ",") {
			policyID = strings.TrimSpace(policyID)
			if policyID == "" {
				continue
			}
			policy := n9eResource(model.ResourceTypeNotificationPolicy, "notify-rule-"+policyID, instance, "notification-policy:"+policyID, now)
			if _, exists := existingResources[policy.ID]; !exists {
				policy.Metadata["declared"] = "false"
				resources = append(resources, policy)
				existingResources[policy.ID] = len(resources) - 1
			}
			relationships = append(relationships, model.Relationship{
				ID:        model.StableID(resource.ID, string(model.RelationshipUses), policy.ID),
				FromID:    resource.ID,
				ToID:      policy.ID,
				Type:      model.RelationshipUses,
				CreatedAt: now,
			})
		}
	}
	n9eApplyHistoryEvents(&resources, existingResources, historyPayload, instance, now)
	n9eApplyBusinessGroups(resources, businessGroupPayload)
	return Snapshot{Resources: resources, Relationships: relationships}, nil
}

type n9eBusinessGroup struct {
	name         string
	labelEnabled bool
}

type n9eRuleHistoryStats struct {
	name               string
	groupID            string
	eventCount         int
	recoveredCount     int
	unrecoveredCount   int
	shortLivedCount    int
	durationTotal      int64
	durationCount      int
	maxDuration        int64
	notificationCount  int64
	recoveryNotifySeen int
	recoveryNotifyOff  int
	firstTrigger       time.Time
	lastTrigger        time.Time
	fingerprints       map[string]bool
	severities         map[string]bool
	notifyRuleSetSeen  int
	notifyRuleSets     map[string]bool
}

func n9eApplyHistoryEvents(resources *[]model.Resource, existingResources map[string]int, payload any, instance string, now time.Time) {
	root, observed := payload.(map[string]any)
	if !observed || root == nil {
		return
	}
	rows := extractObjectRows(root["list"])
	truncated := n9eTruthy(firstString(root, "truncated"))
	windowHours := firstString(root, "window_hours", "windowHours")
	if windowHours == "" {
		windowHours = strconv.Itoa(n9eHistoryWindowHours)
	}
	for index := range *resources {
		if (*resources)[index].Type == model.ResourceTypeAlertRule {
			n9eSetHistoryDefaults(&(*resources)[index], windowHours, truncated)
		}
	}
	statsByRule := make(map[string]*n9eRuleHistoryStats)
	seenEvents := make(map[string]bool)
	for _, row := range rows {
		ruleID := firstString(row, "rule_id", "ruleId")
		if ruleID == "" || ruleID == "0" {
			continue
		}
		eventID := firstString(row, "id", "hash")
		if eventID != "" && seenEvents[eventID] {
			continue
		}
		if eventID != "" {
			seenEvents[eventID] = true
		}
		stats := statsByRule[ruleID]
		if stats == nil {
			stats = &n9eRuleHistoryStats{name: firstString(row, "rule_name", "ruleName"), groupID: firstString(row, "group_id", "groupId"), fingerprints: make(map[string]bool), severities: make(map[string]bool), notifyRuleSets: make(map[string]bool)}
			statsByRule[ruleID] = stats
		}
		stats.eventCount++
		fingerprint := firstString(row, "hash", "fingerprint")
		if fingerprint != "" {
			stats.fingerprints[fingerprint] = true
		}
		if severity := firstString(row, "severity"); severity != "" {
			stats.severities[severity] = true
		}
		_, snakeNotifyRulesPresent := row["notify_rule_ids"]
		_, camelNotifyRulesPresent := row["notifyRuleIds"]
		if snakeNotifyRulesPresent || camelNotifyRulesPresent {
			notifyRuleIDs := n9eScalarList(firstAny(row, "notify_rule_ids", "notifyRuleIds"))
			sort.Strings(notifyRuleIDs)
			stats.notifyRuleSetSeen++
			stats.notifyRuleSets[strings.Join(notifyRuleIDs, ",")] = true
		}
		trigger, hasTrigger := parseN9ETimestamp(firstString(row, "first_trigger_time", "firstTriggerTime", "trigger_time", "triggerTime"))
		recover, hasRecover := parseN9ETimestamp(firstString(row, "recover_time", "recoverTime"))
		recovered := n9eTruthy(firstString(row, "is_recovered", "isRecovered")) || hasRecover
		if recovered {
			stats.recoveredCount++
			_, snakePresent := row["notify_recovered"]
			_, camelPresent := row["notifyRecovered"]
			if snakePresent || camelPresent {
				stats.recoveryNotifySeen++
				if !n9eTruthy(firstString(row, "notify_recovered", "notifyRecovered")) {
					stats.recoveryNotifyOff++
				}
			}
		} else {
			stats.unrecoveredCount++
		}
		if hasTrigger {
			if stats.firstTrigger.IsZero() || trigger.Before(stats.firstTrigger) {
				stats.firstTrigger = trigger
			}
			if trigger.After(stats.lastTrigger) {
				stats.lastTrigger = trigger
			}
		}
		if recovered && hasTrigger && hasRecover && recover.After(trigger) {
			duration := int64(recover.Sub(trigger).Seconds())
			stats.durationTotal += duration
			stats.durationCount++
			if duration > stats.maxDuration {
				stats.maxDuration = duration
			}
			if duration <= 300 {
				stats.shortLivedCount++
			}
		}
		if count, err := strconv.ParseInt(firstString(row, "notify_cur_number", "notifyCurNumber"), 10, 64); err == nil && count > 0 {
			stats.notificationCount += count
		}
	}
	for ruleID, stats := range statsByRule {
		rule := n9eResource(model.ResourceTypeAlertRule, stats.name, instance, "rule:"+ruleID, now)
		if rule.Name == "" {
			rule.Name = "rule-" + ruleID
		}
		index, exists := existingResources[rule.ID]
		if !exists {
			rule.Status = model.ResourceStatusOrphan
			rule.Metadata["declared"] = "false"
			*resources = append(*resources, rule)
			index = len(*resources) - 1
			existingResources[rule.ID] = index
		}
		metadata := (*resources)[index].Metadata
		if metadata == nil {
			metadata = make(map[string]string)
			(*resources)[index].Metadata = metadata
		}
		n9eSetHistoryDefaults(&(*resources)[index], windowHours, truncated)
		metadata["history_window_hours"] = windowHours
		metadata["history_event_count"] = strconv.Itoa(stats.eventCount)
		metadata["history_recovered_count"] = strconv.Itoa(stats.recoveredCount)
		metadata["history_unrecovered_count"] = strconv.Itoa(stats.unrecoveredCount)
		metadata["history_short_lived_count"] = strconv.Itoa(stats.shortLivedCount)
		metadata["history_unique_fingerprint_count"] = strconv.Itoa(len(stats.fingerprints))
		metadata["history_severity_variant_count"] = strconv.Itoa(len(stats.severities))
		metadata["history_notification_route_observed_count"] = strconv.Itoa(stats.notifyRuleSetSeen)
		metadata["history_notification_route_variant_count"] = strconv.Itoa(len(stats.notifyRuleSets))
		metadata["history_notification_count"] = strconv.FormatInt(stats.notificationCount, 10)
		metadata["history_recovery_notification_observed_count"] = strconv.Itoa(stats.recoveryNotifySeen)
		metadata["history_recovery_notification_disabled_count"] = strconv.Itoa(stats.recoveryNotifyOff)
		metadata["history_recovery_notification_enabled_count"] = strconv.Itoa(stats.recoveryNotifySeen - stats.recoveryNotifyOff)
		metadata["history_recovery_notification_all_disabled"] = strconv.FormatBool(stats.recoveryNotifySeen > 0 && stats.recoveryNotifyOff == stats.recoveryNotifySeen)
		metadata["history_max_duration_seconds"] = strconv.FormatInt(stats.maxDuration, 10)
		metadata["history_events_truncated"] = strconv.FormatBool(truncated)
		if stats.eventCount > 0 {
			metadata["history_unrecovered_ratio"] = fmt.Sprintf("%.4f", float64(stats.unrecoveredCount)/float64(stats.eventCount))
			metadata["history_notifications_per_event"] = fmt.Sprintf("%.4f", float64(stats.notificationCount)/float64(stats.eventCount))
		}
		if stats.recoveredCount > 0 {
			metadata["history_short_lived_ratio"] = fmt.Sprintf("%.4f", float64(stats.shortLivedCount)/float64(stats.recoveredCount))
		}
		if stats.durationCount > 0 {
			metadata["history_average_duration_seconds"] = strconv.FormatInt(stats.durationTotal/int64(stats.durationCount), 10)
		}
		if !stats.firstTrigger.IsZero() {
			metadata["history_first_trigger_at"] = stats.firstTrigger.Format(time.RFC3339)
		}
		if !stats.lastTrigger.IsZero() {
			metadata["history_last_trigger_at"] = stats.lastTrigger.Format(time.RFC3339)
		}
		if metadata["group_id"] == "" {
			metadata["group_id"] = stats.groupID
		}
	}
}

func n9eSetHistoryDefaults(resource *model.Resource, windowHours string, truncated bool) {
	if resource.Metadata == nil {
		resource.Metadata = make(map[string]string)
	}
	resource.Metadata["history_observed"] = "true"
	resource.Metadata["history_window_hours"] = windowHours
	resource.Metadata["history_event_count"] = "0"
	resource.Metadata["history_recovered_count"] = "0"
	resource.Metadata["history_unrecovered_count"] = "0"
	resource.Metadata["history_short_lived_count"] = "0"
	resource.Metadata["history_unique_fingerprint_count"] = "0"
	resource.Metadata["history_severity_variant_count"] = "0"
	resource.Metadata["history_notification_route_observed_count"] = "0"
	resource.Metadata["history_notification_route_variant_count"] = "0"
	resource.Metadata["history_notification_count"] = "0"
	resource.Metadata["history_recovery_notification_observed_count"] = "0"
	resource.Metadata["history_recovery_notification_disabled_count"] = "0"
	resource.Metadata["history_recovery_notification_enabled_count"] = "0"
	resource.Metadata["history_recovery_notification_all_disabled"] = "false"
	resource.Metadata["history_max_duration_seconds"] = "0"
	resource.Metadata["history_events_truncated"] = strconv.FormatBool(truncated)
}

func n9eApplyBusinessGroups(resources []model.Resource, payload any) {
	groups := make(map[string]n9eBusinessGroup)
	for _, row := range extractObjectRows(payload) {
		id := firstString(row, "id", "group_id", "groupId")
		name := firstString(row, "name", "group_name", "groupName")
		if id == "" || name == "" {
			continue
		}
		groups[id] = n9eBusinessGroup{name: name, labelEnabled: n9eTruthy(firstString(row, "label_enable", "labelEnable"))}
	}
	for index := range resources {
		groupID := strings.TrimSpace(resources[index].Metadata["group_id"])
		group, ok := groups[groupID]
		if !ok {
			continue
		}
		resources[index].Metadata["business_group_id"] = groupID
		resources[index].Metadata["business_group"] = group.name
		resources[index].Metadata["project"] = group.name
		resources[index].Metadata["business_group_label_binding"] = strconv.FormatBool(group.labelEnabled)
		if resources[index].Metadata["group_name"] == "" {
			resources[index].Metadata["group_name"] = group.name
		}
	}
}

func n9eNotificationPolicyResource(row map[string]any, instance string, now time.Time) (model.Resource, []model.Resource, bool) {
	id := firstString(row, "id", "uuid")
	name := firstString(row, "name", "title")
	if id == "" && name == "" {
		return model.Resource{}, nil, false
	}
	if id == "" {
		id = name
	}
	if name == "" {
		name = "notify-rule-" + id
	}
	configs := extractObjectRows(firstAny(row, "notify_configs", "notifyConfigs"))
	policy := n9eResource(model.ResourceTypeNotificationPolicy, name, instance, "notification-policy:"+id, now)
	policy.Metadata = map[string]string{
		"declared":                     "true",
		model.MetadataEnabled:          firstString(row, "enable", "enabled"),
		model.MetadataPolicyRouteCount: strconv.Itoa(len(configs)),
		"user_group_count":             strconv.Itoa(len(n9eScalarList(firstAny(row, "user_group_ids", "userGroupIds")))),
		"pipeline_count":               strconv.Itoa(len(extractObjectRows(firstAny(row, "pipeline_configs", "pipelineConfigs")))),
	}
	if enabled := firstString(row, "enable", "enabled"); enabled != "" && !n9eTruthy(enabled) {
		policy.Status = model.ResourceStatusDeprecated
	}
	applyN9ETimestamps(&policy, row)
	receivers := make([]model.Resource, 0, len(configs))
	for _, config := range configs {
		channelID := firstString(config, "channel_id", "channelId")
		if channelID == "" {
			continue
		}
		channelIdent := firstString(config, "channel_ident", "channelIdent", "type")
		receiverName := channelIdent
		if receiverName == "" {
			receiverName = "channel-" + channelID
		}
		receiver := n9eResource(model.ResourceTypeReceiver, receiverName, instance, "receiver:channel:"+channelID, now)
		receiver.Metadata = map[string]string{
			"declared":                         "true",
			"receiver_name":                    receiverName,
			"channel_id":                       channelID,
			model.MetadataReceiverIntegrations: channelIdent,
			model.MetadataReceiverRouteCount:   "1",
			"template_id_set":                  strconv.FormatBool(firstString(config, "template_id", "templateId") != ""),
			"severity_count":                   strconv.Itoa(len(n9eScalarList(firstAny(config, "severities")))),
			"time_range_count":                 strconv.Itoa(len(extractObjectRows(firstAny(config, "time_ranges", "timeRanges")))),
			"label_matcher_count":              strconv.Itoa(len(extractObjectRows(firstAny(config, "label_keys", "labelKeys")))),
			"attribute_matcher_count":          strconv.Itoa(len(extractObjectRows(firstAny(config, "attributes")))),
		}
		receivers = append(receivers, receiver)
	}
	return policy, receivers, true
}

func n9eAlertSubscriptionResource(row map[string]any, instance string, now time.Time) (model.Resource, []model.Resource, []string, []string, []string, bool) {
	id := firstString(row, "id", "uuid")
	if id == "" {
		return model.Resource{}, nil, nil, nil, nil, false
	}
	name := firstString(row, "name", "title")
	if name == "" {
		name = "alert-subscription-" + id
	}
	ruleIDs := n9eScalarList(firstAny(row, "rule_ids", "ruleIds"))
	if len(ruleIDs) == 0 {
		if legacyRuleID := firstString(row, "rule_id", "ruleId"); legacyRuleID != "" && legacyRuleID != "0" {
			ruleIDs = []string{legacyRuleID}
		}
	}
	datasourceIDs := n9eDatasourceIDs(row)
	notifyRuleIDs := n9eScalarList(firstAny(row, "notify_rule_ids", "notifyRuleIds"))
	channels := strings.Fields(firstString(row, "new_channels", "newChannels"))
	webhooks := n9eScalarList(firstAny(row, "webhooks", "webhooks_json", "webhooksJson"))
	allDatasources := len(datasourceIDs) == 0
	for _, datasourceID := range datasourceIDs {
		if datasourceID == "0" {
			allDatasources = true
			break
		}
	}
	disabled := n9eTruthy(firstString(row, "disabled", "disable"))
	subscription := n9eResource(model.ResourceTypeNotificationPolicy, name, instance, "alert-subscription:"+id, now)
	subscription.Metadata = map[string]string{
		"declared":                             "true",
		model.MetadataEnabled:                  strconv.FormatBool(!disabled),
		"policy_kind":                          "alert_subscription",
		"subscription_id":                      id,
		"group_id":                             firstString(row, "group_id", "groupId"),
		"product":                              firstString(row, "prod", "product"),
		"category":                             firstString(row, "cate", "category"),
		"subscription_notify_version":          firstString(row, "notify_version", "notifyVersion"),
		"subscription_rule_filter_count":       strconv.Itoa(len(ruleIDs)),
		"subscription_datasource_filter_count": strconv.Itoa(len(datasourceIDs)),
		"subscription_severity_count":          strconv.Itoa(len(n9eScalarList(firstAny(row, "severities")))),
		"subscription_tag_matcher_count":       strconv.Itoa(len(extractObjectRows(firstAny(row, "tags")))),
		"subscription_group_matcher_count":     strconv.Itoa(len(extractObjectRows(firstAny(row, "busi_groups", "busiGroups")))),
		"subscription_notify_rule_count":       strconv.Itoa(len(notifyRuleIDs)),
		"subscription_channel_count":           strconv.Itoa(len(channels)),
		"subscription_webhook_count":           strconv.Itoa(len(webhooks)),
		"subscription_user_group_count":        strconv.Itoa(len(strings.Fields(firstString(row, "user_group_ids", "userGroupIds")))),
		"subscription_note_present":            strconv.FormatBool(strings.TrimSpace(firstString(row, "note")) != ""),
		"subscription_for_duration_seconds":    firstString(row, "for_duration", "forDuration"),
		"datasource_scope":                     map[bool]string{true: "all", false: "selected"}[allDatasources],
		model.MetadataPolicyRouteCount:         strconv.Itoa(len(notifyRuleIDs) + len(channels) + len(webhooks)),
	}
	if disabled {
		subscription.Status = model.ResourceStatusDeprecated
	}
	applyN9ETimestamps(&subscription, row)

	receivers := make([]model.Resource, 0, len(channels)+1)
	for _, channel := range channels {
		receiver := n9eResource(model.ResourceTypeReceiver, channel, instance, "receiver:alert-subscription:"+id+":channel:"+channel, now)
		receiver.Metadata = map[string]string{
			"declared":                         "true",
			"receiver_name":                    channel,
			model.MetadataReceiverIntegrations: channel,
			model.MetadataReceiverRouteCount:   "1",
		}
		receivers = append(receivers, receiver)
	}
	if len(webhooks) > 0 {
		insecureCount := 0
		for _, webhook := range webhooks {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(webhook)), "http://") {
				insecureCount++
			}
		}
		receiver := n9eResource(model.ResourceTypeReceiver, "webhook", instance, "receiver:alert-subscription:"+id+":webhook", now)
		receiver.Metadata = map[string]string{
			"declared":                                  "true",
			"receiver_name":                             "webhook",
			model.MetadataReceiverIntegrations:          "webhook",
			model.MetadataReceiverRouteCount:            "1",
			model.MetadataReceiverInsecureEndpointCount: strconv.Itoa(insecureCount),
			"endpoint_count":                            strconv.Itoa(len(webhooks)),
		}
		receivers = append(receivers, receiver)
	}
	return subscription, receivers, ruleIDs, datasourceIDs, notifyRuleIDs, true
}

type n9eSilenceMatcherDetail struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex"`
	IsEqual bool   `json:"is_equal"`
}

func n9eAlertMuteResource(row map[string]any, instance string, now time.Time) (model.Resource, []string, bool) {
	id := firstString(row, "id", "uuid")
	if id == "" {
		return model.Resource{}, nil, false
	}
	comment := firstString(row, "note", "cause", "comment")
	name := firstString(row, "cause", "note", "name")
	if name == "" {
		name = "mute-" + id
	}
	resource := n9eResource(model.ResourceTypeSilence, name, instance, "silence:"+id, now)
	resource.Metadata = map[string]string{
		model.MetadataSilenceID:        id,
		model.MetadataSilenceCreatedBy: firstString(row, "create_by", "createBy", "created_by", "createdBy"),
		model.MetadataSilenceComment:   comment,
		"group_id":                     firstString(row, "group_id", "groupId"),
		"category":                     firstString(row, "cate", "category"),
		"product":                      firstString(row, "prod", "product"),
		"mute_type":                    firstString(row, "mute_type", "muteType"),
		"mute_time_type":               firstString(row, "mute_time_type", "muteTimeType"),
		"severity_count":               strconv.Itoa(len(n9eScalarList(firstAny(row, "severities")))),
		"periodic_window_count":        strconv.Itoa(len(extractObjectRows(firstAny(row, "periodic_mutes", "periodicMutes")))),
	}
	disabled := n9eTruthy(firstString(row, "disabled", "disable"))
	periodic := firstString(row, "mute_time_type", "muteTimeType") == "1"
	state := "pending"
	if disabled {
		state = "disabled"
		resource.Status = model.ResourceStatusDeprecated
	} else if periodic {
		if n9eTruthy(firstString(row, "activated", "active")) {
			state = "active"
		}
	} else {
		startsAt, hasStartsAt := parseN9ETimestamp(firstString(row, "btime", "starts_at", "startsAt"))
		endsAt, hasEndsAt := parseN9ETimestamp(firstString(row, "etime", "ends_at", "endsAt"))
		if hasStartsAt {
			resource.Metadata[model.MetadataStartsAt] = startsAt.Format(time.RFC3339)
			resource.CreatedAt = startsAt
		}
		if hasEndsAt {
			resource.Metadata[model.MetadataEndsAt] = endsAt.Format(time.RFC3339)
		}
		if hasEndsAt && now.After(endsAt) {
			state = "expired"
			resource.Status = model.ResourceStatusDeprecated
		} else if hasStartsAt && !now.Before(startsAt) {
			state = "active"
		}
	}
	resource.Metadata[model.MetadataSilenceState] = state
	if updatedAt, ok := parseN9ETimestamp(firstString(row, "update_at", "updateAt", "updated_at", "updatedAt")); ok {
		resource.UpdatedAt = updatedAt
		resource.Metadata[model.MetadataUpdatedAt] = updatedAt.Format(time.RFC3339)
	}
	details, display, positive, negative, regexCount := n9eMuteMatchers(firstAny(row, "tags", "matchers"))
	resource.Metadata[model.MetadataSilenceMatcherCount] = strconv.Itoa(len(details))
	resource.Metadata[model.MetadataSilencePositiveCount] = strconv.Itoa(positive)
	resource.Metadata[model.MetadataSilenceNegativeCount] = strconv.Itoa(negative)
	resource.Metadata[model.MetadataSilenceRegexCount] = strconv.Itoa(regexCount)
	if len(display) > 0 {
		resource.Metadata[model.MetadataSilenceMatchers] = strings.Join(display, ",")
	}
	if encoded, err := json.Marshal(details); err == nil && len(details) > 0 {
		resource.Metadata[model.MetadataSilenceMatcherDetails] = string(encoded)
	}
	datasourceIDs := n9eDatasourceIDs(row)
	for _, datasourceID := range datasourceIDs {
		if datasourceID == "0" {
			resource.Metadata["datasource_scope"] = "all"
			break
		}
	}
	return resource, datasourceIDs, true
}

func n9eMuteMatchers(value any) ([]n9eSilenceMatcherDetail, []string, int, int, int) {
	rows := extractObjectRows(value)
	if rows == nil {
		if direct, ok := value.([]any); ok {
			rows = make([]map[string]any, 0, len(direct))
			for _, item := range direct {
				if row, ok := item.(map[string]any); ok {
					rows = append(rows, row)
				}
			}
		}
	}
	details := make([]n9eSilenceMatcherDetail, 0, len(rows))
	display := make([]string, 0, len(rows))
	positive, negative, regexCount := 0, 0, 0
	for _, row := range rows {
		name := firstString(row, "key", "name", "label")
		op := firstString(row, "func", "op", "operator")
		if name == "" || op == "" {
			continue
		}
		matcherValue := n9eMatcherValue(firstAny(row, "value", "values"))
		isRegex := op == "=~" || op == "!~"
		isEqual := op != "!=" && op != "!~" && op != "not in"
		details = append(details, n9eSilenceMatcherDetail{Name: name, Value: matcherValue, IsRegex: isRegex, IsEqual: isEqual})
		display = append(display, name+" "+op+" "+matcherValue)
		if isEqual {
			positive++
		} else {
			negative++
		}
		if isRegex {
			regexCount++
		}
	}
	return details, display, positive, negative, regexCount
}

func n9eMatcherValue(value any) string {
	if values := n9eScalarList(value); len(values) > 0 {
		return strings.Join(values, "|")
	}
	if encoded, err := json.Marshal(value); err == nil && string(encoded) != "null" {
		return string(encoded)
	}
	return ""
}

func n9ePayloadTotal(payload any) int {
	switch typed := payload.(type) {
	case map[string]any:
		if raw, ok := typed["total"]; ok {
			value, err := strconv.Atoi(scalarString(raw))
			if err == nil {
				return value
			}
		}
		for _, key := range []string{"data", "dat"} {
			if total := n9ePayloadTotal(typed[key]); total > 0 {
				return total
			}
		}
	}
	return 0
}

func n9eRuntimeCoverageResource(ruleRows []map[string]any, eventPayload any, historyPayload any, instance string, now time.Time) model.Resource {
	resource := n9eResource(model.ResourceTypeInstance, "N9E Runtime", instance, "runtime", now)
	resource.Metadata[model.MetadataN9ERuntime] = "true"
	resource.Metadata[model.MetadataN9ERuleDiscoveryAvailable] = "true"
	resource.Metadata[model.MetadataN9ERuleCount] = strconv.Itoa(len(ruleRows))
	n9eSetEventCoverageMetadata(
		resource.Metadata,
		eventPayload,
		model.MetadataN9ECurrentAlertDiscoveryAvailable,
		model.MetadataN9ECurrentAlertEventCount,
		model.MetadataN9ECurrentAlertEventTotal,
		model.MetadataN9ECurrentAlertEventsTruncated,
	)
	n9eSetEventCoverageMetadata(
		resource.Metadata,
		historyPayload,
		model.MetadataN9EHistoryDiscoveryAvailable,
		model.MetadataN9EHistoryEventCount,
		model.MetadataN9EHistoryEventTotal,
		model.MetadataN9EHistoryEventsTruncated,
	)
	if root, ok := historyPayload.(map[string]any); ok {
		if window := scalarString(root["window_hours"]); window != "" {
			resource.Metadata[model.MetadataN9EHistoryWindowHours] = window
		}
	}
	return resource
}

func n9eSetEventCoverageMetadata(metadata map[string]string, payload any, availabilityKey string, countKey string, totalKey string, truncatedKey string) {
	available := payload != nil
	metadata[availabilityKey] = strconv.FormatBool(available)
	if !available {
		return
	}
	count := len(extractObjectRows(payload))
	total := n9ePayloadTotal(payload)
	metadata[countKey] = strconv.Itoa(count)
	metadata[totalKey] = strconv.Itoa(total)
	metadata[truncatedKey] = strconv.FormatBool(n9ePayloadTruncated(payload))
}

func n9ePayloadTruncated(payload any) bool {
	root, ok := payload.(map[string]any)
	if !ok {
		return false
	}
	raw, exists := root["truncated"]
	if !exists {
		return false
	}
	value, err := strconv.ParseBool(strings.TrimSpace(scalarString(raw)))
	return err == nil && value
}

func n9eCurrentEventResource(row map[string]any, instance string, now time.Time) (model.Resource, model.Resource, model.Relationship, bool) {
	ruleName := firstString(row, "rule_name", "ruleName", "alertname", "name")
	ruleID := firstString(row, "rule_id", "ruleId")
	if ruleName == "" && ruleID == "" {
		return model.Resource{}, model.Resource{}, model.Relationship{}, false
	}
	if ruleName == "" {
		ruleName = "rule-" + ruleID
	}
	fingerprint := firstString(row, "hash", "fingerprint", "id")
	if fingerprint == "" {
		fingerprint = model.StableID(ruleID, ruleName, firstString(row, "datasource_id", "target_ident", "trigger_time"))
	}
	alert := n9eResource(model.ResourceTypeAlert, ruleName, instance, "alert:"+fingerprint, now)
	alert.Labels = stringMapFromAny(firstAny(row, "tags_map", "tagsMap", "tags"))
	alert.Metadata = map[string]string{
		model.MetadataAlertState:  "active",
		model.MetadataAlertValue:  firstString(row, "trigger_value", "triggerValue"),
		model.MetadataFingerprint: fingerprint,
		model.MetadataPromQL:      firstString(row, "prom_ql", "promql", "promQl"),
		model.MetadataAlertFor:    firstString(row, "prom_for_duration", "promForDuration"),
		"severity":                firstString(row, "severity"),
		"datasource_id":           firstString(row, "datasource_id", "datasourceId"),
		"group_id":                firstString(row, "group_id", "groupId"),
		"group_name":              firstString(row, "group_name", "groupName"),
		"target_ident":            firstString(row, "target_ident", "targetIdent"),
	}
	for key, value := range stringMapFromAny(firstAny(row, "annotations")) {
		alert.Metadata["annotation."+key] = value
	}
	startsAt, hasStartsAt := parseN9ETimestamp(firstString(row, "first_trigger_time", "firstTriggerTime", "trigger_time", "triggerTime"))
	if hasStartsAt {
		alert.CreatedAt = startsAt
		alert.Metadata[model.MetadataStartsAt] = startsAt.Format(time.RFC3339)
	}
	if updatedAt, ok := parseN9ETimestamp(firstString(row, "last_eval_time", "lastEvalTime", "trigger_time", "triggerTime")); ok {
		alert.UpdatedAt = updatedAt
		alert.Metadata[model.MetadataUpdatedAt] = updatedAt.Format(time.RFC3339)
	}
	ruleExternalID := ruleID
	if ruleExternalID == "" {
		ruleExternalID = string(model.ResourceTypeAlertRule) + ":" + ruleName
	}
	rule := n9eResource(model.ResourceTypeAlertRule, ruleName, instance, "rule:"+ruleExternalID, now)
	rule.Metadata["group_id"] = firstString(row, "group_id", "groupId")
	for key, value := range alert.Labels {
		rule.Labels[key] = value
	}
	relationship := model.Relationship{
		ID:        model.StableID(alert.ID, string(model.RelationshipReferences), rule.ID),
		FromID:    alert.ID,
		ToID:      rule.ID,
		Type:      model.RelationshipReferences,
		CreatedAt: now,
	}
	return alert, rule, relationship, true
}

func n9eDatasourceCatalog(payload any, instance string, now time.Time) map[string]model.Resource {
	resources := make(map[string]model.Resource)
	for _, row := range extractObjectRows(payload) {
		id := firstString(row, "id", "uid")
		name := firstString(row, "name", "identifier")
		if id == "" && name == "" {
			continue
		}
		if name == "" {
			name = id
		}
		externalID := id
		if externalID == "" {
			externalID = name
		}
		resource := n9eResource(model.ResourceTypeDatasource, name, instance, "datasource:"+externalID, now)
		resource.Metadata = map[string]string{
			model.MetadataDatasourceUID:  id,
			model.MetadataDatasourceType: firstString(row, "plugin_type", "pluginType", "type"),
			"datasource_id":              id,
			"datasource_name":            name,
			"category":                   firstString(row, "category"),
			"cluster":                    firstString(row, "cluster_name", "clusterName", "cluster"),
			"identifier":                 firstString(row, "identifier"),
		}
		if datasourceURL := firstNestedString(firstAny(row, "http"), "url"); datasourceURL != "" {
			resource.Metadata[model.MetadataDatasourceURL] = datasourceURL
		}
		status := strings.ToLower(firstString(row, "status"))
		if status != "" {
			resource.Metadata["status"] = status
		}
		if status == "disabled" {
			resource.Status = model.ResourceStatusDeprecated
		}
		applyN9ETimestamps(&resource, row)
		resources[resource.ID] = resource
	}
	return resources
}

func n9eRuleResource(row map[string]any, instance string, now time.Time) (model.Resource, bool) {
	name := firstString(row, "name", "rule_name", "ruleName", "title", "alert", "alertname", "record", "record_name", "recordName")
	query := n9eRuleQuery(row)
	if name == "" {
		name = query
	}
	if name == "" {
		return model.Resource{}, false
	}

	resourceType := n9eRuleResourceType(row)

	externalID := firstString(row, "id", "ident", "uuid")
	if externalID == "" {
		externalID = string(resourceType) + ":" + name
	}

	resource := n9eResource(resourceType, name, instance, "rule:"+externalID, now)
	resource.Labels = stringMapFromAny(firstAny(row, "labels", "tags"))
	for key, value := range n9eInlineLabels(row) {
		if _, exists := resource.Labels[key]; !exists {
			resource.Labels[key] = value
		}
	}
	resource.Metadata = map[string]string{
		model.MetadataHealth:  "ok",
		model.MetadataEnabled: firstString(row, "enabled", "enable"),
	}
	setQueryMetadata(resource.Metadata, model.MetadataPromQL, query)
	for key, value := range n9eMetadata(row) {
		if value == "" {
			continue
		}
		resource.Metadata[key] = value
	}
	if resource.Type == model.ResourceTypeRecordingRule && resource.Metadata[model.MetadataRecordingRuleOutput] == "" {
		resource.Metadata[model.MetadataRecordingRuleOutput] = n9eRecordingOutput(row, name)
	}
	if disabledValue := firstString(row, "disabled", "disable"); disabledValue != "" {
		resource.Metadata[model.MetadataDisabled] = disabledValue
		if resource.Metadata[model.MetadataEnabled] == "" {
			resource.Metadata[model.MetadataEnabled] = strconv.FormatBool(!n9eTruthy(disabledValue))
		}
	}
	for key, value := range stringMapFromAny(firstAny(row, "annotations")) {
		resource.Metadata["annotation."+key] = value
	}
	applyN9ETimestamps(&resource, row)
	if isN9EDisabled(row) {
		resource.Status = model.ResourceStatusDeprecated
		resource.Metadata[model.MetadataDisabled] = "true"
	}
	annotateSLORuleMetadata(&resource)
	return resource, true
}

func n9eRuleResourceType(row map[string]any) model.ResourceType {
	ruleType := strings.ToLower(firstString(row, "type", "kind", "rule_type", "ruleType", "cate", "category"))
	if strings.Contains(ruleType, "record") || strings.Contains(ruleType, "recording") {
		return model.ResourceTypeRecordingRule
	}
	if n9eTruthy(firstString(row, "is_recording", "isRecording", "recording")) {
		return model.ResourceTypeRecordingRule
	}
	if firstString(row, "record", "record_name", "recordName") != "" {
		return model.ResourceTypeRecordingRule
	}
	return model.ResourceTypeAlertRule
}

func n9eRecordingOutput(row map[string]any, fallback string) string {
	if output := firstString(row, "record", "record_name", "recordName", "output", "metric", "metric_name", "metricName"); output != "" {
		return output
	}
	return strings.TrimSpace(fallback)
}

func n9eInlineLabels(row map[string]any) map[string]string {
	labels := make(map[string]string)
	for _, key := range []string{"severity", "priority", "team", "service", "tenant", "cluster", "owner", "squad", "maintainer", "responsible"} {
		if value := firstString(row, key); value != "" {
			labels[key] = value
		}
	}
	if owner := firstString(row, "owner", "owner_name", "ownerName", "maintainer", "maintainer_name", "maintainerName", "responsible", "responsible_name", "responsibleName"); owner != "" {
		labels[model.MetadataOwner] = owner
	}
	return labels
}

func n9eMetadata(row map[string]any) map[string]string {
	datasourceIDs := n9eDatasourceIDs(row)
	notifyRuleIDs := n9eScalarList(firstAny(row, "notify_rule_ids", "notifyRuleIds"))
	datasourceID := firstString(row, "datasource_id", "datasourceId", "datasource")
	if datasourceID == "" && len(datasourceIDs) == 1 {
		datasourceID = datasourceIDs[0]
	}
	return map[string]string{
		"datasource_id":                   datasourceID,
		"datasource_ids":                  strings.Join(datasourceIDs, ","),
		"datasource_count":                strconv.Itoa(len(datasourceIDs)),
		"notify_rule_ids":                 strings.Join(notifyRuleIDs, ","),
		"notify_rule_count":               strconv.Itoa(len(notifyRuleIDs)),
		"datasource_name":                 firstString(row, "datasource_name", "datasourceName"),
		"cluster":                         firstString(row, "cluster", "cluster_name", "clusterName"),
		"group_id":                        firstString(row, "group_id", "groupId", "group"),
		"group_name":                      firstString(row, "group_name", "groupName"),
		model.MetadataRuleGroup:           firstString(row, "group_name", "groupName"),
		model.MetadataAlertFor:            firstString(row, "for", "duration", "hold_duration", "holdDuration", "prom_for_duration", "promForDuration"),
		model.MetadataRecordingRuleOutput: firstString(row, "record", "record_name", "recordName", "output", "metric", "metric_name", "metricName"),
		"severity":                        firstString(row, "severity", "priority"),
		model.MetadataOwner:               firstString(row, "owner", "owner_name", "ownerName", "maintainer", "maintainer_name", "maintainerName", "responsible", "responsible_name", "responsibleName"),
		"maintainer":                      firstString(row, "maintainer", "maintainer_name", "maintainerName"),
		"responsible":                     firstString(row, "responsible", "responsible_name", "responsibleName"),
		"squad":                           firstString(row, "squad", "squad_name", "squadName"),
		"runbook_url":                     firstString(row, "runbook_url", "runbookUrl", "runbook"),
		"note":                            firstString(row, "note", "remark", "description"),
	}
}

func n9eDatasourceResources(row map[string]any, instance string, now time.Time) []model.Resource {
	datasourceIDs := n9eDatasourceIDs(row)
	datasourceName := firstString(row, "datasource_name", "datasourceName")
	datasourceURL := firstString(row, "datasource_url", "datasourceUrl")
	if len(datasourceIDs) == 0 && (datasourceName != "" || datasourceURL != "") {
		datasourceIDs = []string{""}
	}
	resources := make([]model.Resource, 0, len(datasourceIDs))
	for _, datasourceID := range datasourceIDs {
		name := datasourceID
		if len(datasourceIDs) == 1 && datasourceName != "" {
			name = datasourceName
		}
		if name == "" {
			name = datasourceURL
		}
		externalID := datasourceID
		if externalID == "" {
			externalID = name
		}
		resource := n9eResource(model.ResourceTypeDatasource, name, instance, "datasource:"+externalID, now)
		resource.Metadata = map[string]string{
			model.MetadataDatasourceType: firstString(row, "datasource_type", "datasourceType"),
			"datasource_id":              datasourceID,
			"datasource_name":            datasourceName,
		}
		if resource.Metadata[model.MetadataDatasourceType] == "" {
			resource.Metadata[model.MetadataDatasourceType] = "prometheus"
		}
		if datasourceID != "" {
			resource.Metadata[model.MetadataDatasourceUID] = datasourceID
		}
		if datasourceURL != "" {
			resource.Metadata[model.MetadataDatasourceURL] = datasourceURL
		}
		applyN9ETimestamps(&resource, row)
		resources = append(resources, resource)
	}
	return resources
}

func n9eDatasourceIDs(row map[string]any) []string {
	value := firstAny(row, "datasource_ids", "datasourceIds")
	if value == nil {
		value = firstAny(row, "datasource_id", "datasourceId", "datasource")
	}
	return n9eScalarList(value)
}

func n9eScalarList(value any) []string {
	if raw, ok := value.(string); ok {
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "[") {
			var decoded any
			decoder := json.NewDecoder(strings.NewReader(raw))
			decoder.UseNumber()
			if decoder.Decode(&decoded) == nil {
				return n9eScalarList(decoded)
			}
		}
	}
	values := make([]string, 0)
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if scalar := scalarString(item); scalar != "" {
				values = append(values, scalar)
			}
		}
	default:
		if scalar := scalarString(typed); scalar != "" {
			values = append(values, scalar)
		}
	}
	return values
}

func n9eResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), n9eSystem, instance, externalID)
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: n9eSystem, Instance: instance, ExternalID: externalID},
		Metadata:  map[string]string{},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func extractObjectRows(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		rows := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if row, ok := item.(map[string]any); ok {
				rows = append(rows, row)
			}
		}
		return rows
	case map[string]any:
		for _, key := range []string{"data", "dat", "list", "rules", "items"} {
			if child, ok := typed[key]; ok {
				if rows := extractObjectRows(child); len(rows) > 0 {
					return rows
				}
			}
		}
	}
	return nil
}

func firstAny(row map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := row[key]; ok {
			return value
		}
	}
	return nil
}

func firstString(row map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := row[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case json.Number:
			return typed.String()
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(typed)
		}
	}
	return ""
}

func n9eRuleQuery(row map[string]any) string {
	if query := firstString(row, "promql", "prom_ql", "promQl", "expr", "expression", "query"); query != "" {
		return query
	}
	for _, key := range []string{"queries", "query_configs", "queryConfigs", "exprs", "rule_config", "ruleConfig"} {
		if query := firstNestedString(firstAny(row, key), "promql", "prom_ql", "promQl", "expr", "expression", "query"); query != "" {
			return query
		}
	}
	return ""
}

func firstNestedString(value any, keys ...string) string {
	switch typed := value.(type) {
	case string:
		var decoded any
		decoder := json.NewDecoder(strings.NewReader(typed))
		decoder.UseNumber()
		if decoder.Decode(&decoded) == nil {
			return firstNestedString(decoded, keys...)
		}
	case map[string]any:
		if query := firstString(typed, keys...); query != "" {
			return query
		}
		for _, child := range typed {
			if query := firstNestedString(child, keys...); query != "" {
				return query
			}
		}
	case []any:
		for _, child := range typed {
			if query := firstNestedString(child, keys...); query != "" {
				return query
			}
		}
	}
	return ""
}

func stringMapFromAny(value any) map[string]string {
	result := make(map[string]string)
	switch typed := value.(type) {
	case map[string]any:
		for key, raw := range typed {
			if value := scalarString(raw); value != "" {
				result[key] = value
			}
		}
	case []any:
		for _, item := range typed {
			switch entry := item.(type) {
			case string:
				key, value, ok := strings.Cut(entry, "=")
				if ok && strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
					result[strings.TrimSpace(key)] = strings.TrimSpace(value)
				}
			case map[string]any:
				key := firstString(entry, "key", "name", "label")
				value := firstString(entry, "value", "val")
				if key != "" && value != "" {
					result[key] = value
				}
			}
		}
	}
	return result
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	}
	return ""
}

func applyN9ETimestamps(resource *model.Resource, row map[string]any) {
	if resource == nil {
		return
	}
	if resource.Metadata == nil {
		resource.Metadata = map[string]string{}
	}
	if createdAt, ok := parseN9ETimestamp(firstString(row, "created_at", "createdAt", "create_at", "createAt", "create_time", "createTime", "created")); ok {
		resource.CreatedAt = createdAt
		resource.Metadata["created_at"] = createdAt.Format(time.RFC3339)
	}
	if updatedAt, ok := parseN9ETimestamp(firstString(row, "updated_at", "updatedAt", "update_at", "updateAt", "update_time", "updateTime", "last_updated", "lastUpdated", "updated")); ok {
		resource.UpdatedAt = updatedAt
		resource.Metadata[model.MetadataUpdatedAt] = updatedAt.Format(time.RFC3339)
	}
}

func parseN9ETimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	number, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || number <= 0 {
		return time.Time{}, false
	}
	if number > 1_000_000_000_000 {
		return time.UnixMilli(number).UTC(), true
	}
	return time.Unix(number, 0).UTC(), true
}

func isN9EDisabled(row map[string]any) bool {
	disabled := strings.ToLower(firstString(row, "disabled", "disable"))
	if n9eTruthy(disabled) {
		return true
	}
	enabled := strings.ToLower(firstString(row, "enabled", "enable"))
	return enabled == "false" || enabled == "0" || enabled == "no"
}

func n9eTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}
