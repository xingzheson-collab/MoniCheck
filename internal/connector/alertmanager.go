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

	prommodel "github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

const alertmanagerSystem = "alertmanager"

type AlertmanagerConnector struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewAlertmanagerConnector(baseURL string, token string) (*AlertmanagerConnector, error) {
	return NewAlertmanagerConnectorWithOptions(baseURL, HTTPOptions{BearerToken: token, Timeout: 10 * time.Second})
}

func NewAlertmanagerConnectorWithOptions(baseURL string, options HTTPOptions) (*AlertmanagerConnector, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid alertmanager url: %s", baseURL)
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &AlertmanagerConnector{
		baseURL: parsed.String(),
		token:   strings.TrimSpace(options.BearerToken),
		client:  client,
	}, nil
}

func (c *AlertmanagerConnector) ID() string {
	return "alertmanager"
}

func (c *AlertmanagerConnector) Name() string {
	return "Alertmanager Connector"
}

func (c *AlertmanagerConnector) Sync(ctx context.Context) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/alerts", nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Snapshot{}, fmt.Errorf("alertmanager /api/v2/alerts returned status %d", resp.StatusCode)
	}

	var alerts []alertmanagerAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return Snapshot{}, err
	}
	status, statusErr := c.fetchStatus(ctx)
	config := ""
	if status != nil {
		config = status.Config.Original
	}
	silences, silencesErr := c.fetchSilences(ctx)
	snapshot := alertmanagerSnapshotFromAlertsConfigSilencesAndStatus(alerts, config, silences, status, c.baseURL, time.Now().UTC())
	snapshot.Diagnostics = []model.Diagnostic{
		c.optionalDiagnostic("alertmanager_status_config", "Alertmanager status config", "/api/v2/status", statusErr),
		c.optionalDiagnostic("alertmanager_silences", "Alertmanager silences", "/api/v2/silences", silencesErr),
	}
	snapshot.Partial = statusErr != nil || silencesErr != nil
	return snapshot, nil
}

func (c *AlertmanagerConnector) fetchStatus(ctx context.Context) (*alertmanagerStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("alertmanager /api/v2/status returned status %d", resp.StatusCode)
	}
	var status alertmanagerStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	if strings.TrimSpace(status.Config.Original) == "" {
		return nil, fmt.Errorf("alertmanager /api/v2/status returned empty original config")
	}
	return &status, nil
}

func (c *AlertmanagerConnector) fetchSilences(ctx context.Context) ([]alertmanagerSilence, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/silences", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("alertmanager /api/v2/silences returned status %d", resp.StatusCode)
	}
	var silences []alertmanagerSilence
	if err := json.NewDecoder(resp.Body).Decode(&silences); err != nil {
		return nil, err
	}
	return silences, nil
}

func (c *AlertmanagerConnector) optionalDiagnostic(id string, name string, path string, err error) model.Diagnostic {
	status := model.ExecutionStatusSucceeded
	message := name + " discovery completed"
	if err != nil {
		status = model.ExecutionStatusWarning
		message = name + " endpoint is unavailable; core alert discovery continued"
	}
	diagnostic := model.Diagnostic{
		ID:      id,
		Name:    name,
		Status:  status,
		Message: message,
		Metadata: map[string]string{
			"endpoint": path,
			"optional": "true",
			"system":   alertmanagerSystem,
		},
	}
	if err != nil {
		diagnostic.Metadata["error"] = err.Error()
	}
	return diagnostic
}

type alertmanagerAlert struct {
	Labels       map[string]string           `json:"labels"`
	Annotations  map[string]string           `json:"annotations"`
	StartsAt     time.Time                   `json:"startsAt"`
	EndsAt       time.Time                   `json:"endsAt"`
	UpdatedAt    time.Time                   `json:"updatedAt"`
	GeneratorURL string                      `json:"generatorURL"`
	Fingerprint  string                      `json:"fingerprint"`
	Status       alertmanagerAlertStatus     `json:"status"`
	Receivers    []alertmanagerAlertReceiver `json:"receivers"`
}

type alertmanagerAlertStatus struct {
	State       string   `json:"state"`
	SilencedBy  []string `json:"silencedBy"`
	InhibitedBy []string `json:"inhibitedBy"`
}

type alertmanagerAlertReceiver struct {
	Name string `json:"name"`
}

type alertmanagerStatus struct {
	Cluster     alertmanagerClusterStatus `json:"cluster"`
	VersionInfo alertmanagerVersionInfo   `json:"versionInfo"`
	Config      alertmanagerStatusConfig  `json:"config"`
	Uptime      time.Time                 `json:"uptime"`
}

type alertmanagerClusterStatus struct {
	Name   string                   `json:"name"`
	Status string                   `json:"status"`
	Peers  []alertmanagerPeerStatus `json:"peers"`
}

type alertmanagerPeerStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type alertmanagerVersionInfo struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Branch    string `json:"branch"`
	BuildUser string `json:"buildUser"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
}

type alertmanagerStatusConfig struct {
	Original string `json:"original"`
}

type alertmanagerSilence struct {
	ID        string                    `json:"id"`
	Matchers  []alertmanagerMatcher     `json:"matchers"`
	StartsAt  time.Time                 `json:"startsAt"`
	EndsAt    time.Time                 `json:"endsAt"`
	UpdatedAt time.Time                 `json:"updatedAt"`
	CreatedBy string                    `json:"createdBy"`
	Comment   string                    `json:"comment"`
	Status    alertmanagerSilenceStatus `json:"status"`
}

type alertmanagerMatcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual bool   `json:"isEqual"`
}

type alertmanagerSilenceStatus struct {
	State string `json:"state"`
}

func alertmanagerSnapshotFromAlerts(alerts []alertmanagerAlert, instance string, now time.Time) Snapshot {
	return alertmanagerSnapshotFromAlertsAndConfig(alerts, "", instance, now)
}

func alertmanagerSnapshotFromAlertsAndConfig(alerts []alertmanagerAlert, config string, instance string, now time.Time) Snapshot {
	return alertmanagerSnapshotFromAlertsConfigAndSilences(alerts, config, nil, instance, now)
}

func alertmanagerSnapshotFromAlertsConfigAndSilences(alerts []alertmanagerAlert, config string, silences []alertmanagerSilence, instance string, now time.Time) Snapshot {
	return alertmanagerSnapshotFromAlertsConfigSilencesAndStatus(alerts, config, silences, nil, instance, now)
}

func alertmanagerSnapshotFromAlertsConfigSilencesAndStatus(alerts []alertmanagerAlert, config string, silences []alertmanagerSilence, status *alertmanagerStatus, instance string, now time.Time) Snapshot {
	resourcesByID := make(map[string]model.Resource)
	relationships := make([]model.Relationship, 0)
	var runtime *model.Resource
	if status != nil {
		resource := alertmanagerRuntimeResource(*status, instance, now)
		runtime = &resource
		resourcesByID[resource.ID] = resource
	}
	declaredReceivers, routeReceivers, receiverIntegrations := alertmanagerConfigReceivers(config)
	insecureEndpointCounts := alertmanagerReceiverInsecureEndpointCounts(config)
	for receiver := range declaredReceivers {
		resource := alertmanagerReceiverResource(receiver, instance, now)
		resource.Metadata["declared"] = "true"
		if integrations := receiverIntegrations[receiver]; len(integrations) > 0 {
			resource.Metadata[model.MetadataReceiverIntegrations] = strings.Join(integrations, ",")
		}
		if routeReceivers[receiver] {
			resource.Metadata["referenced_by_route"] = "true"
		}
		resource.Metadata[model.MetadataReceiverInsecureEndpointCount] = strconv.Itoa(insecureEndpointCounts[receiver])
		resourcesByID[resource.ID] = resource
	}
	for receiver := range routeReceivers {
		resource := alertmanagerReceiverResource(receiver, instance, now)
		if declaredReceivers[receiver] {
			continue
		}
		resource.Metadata["declared"] = "false"
		resource.Metadata["referenced_by_route"] = "true"
		resourcesByID[resource.ID] = resource
	}
	if policyStats, ok := alertmanagerRoutingPolicyStats(config); ok {
		policy := alertmanagerResource(model.ResourceTypeNotificationPolicy, "default", instance, "notification-policy:default", now)
		applyRoutingPolicyMetadata(&policy, policyStats)
		resourcesByID[policy.ID] = policy
		if runtime != nil {
			relationships = append(relationships, alertmanagerRelationship(runtime.ID, policy.ID, model.RelationshipUses, now))
		}
		for receiverName := range routeReceivers {
			receiver := alertmanagerReceiverResource(receiverName, instance, now)
			relationships = append(relationships, alertmanagerRelationship(policy.ID, receiver.ID, model.RelationshipUses, now))
		}
		for _, interval := range alertmanagerTimeIntervals(config) {
			resource := alertmanagerResource(model.ResourceTypeTimeInterval, interval.name, instance, "time-interval:"+interval.name, now)
			resource.Metadata[model.MetadataTimeIntervalDeclared] = strconv.FormatBool(interval.declared)
			resource.Metadata[model.MetadataTimeIntervalSpecCount] = strconv.Itoa(interval.specCount)
			resource.Metadata[model.MetadataTimeIntervalMuteRefCount] = strconv.Itoa(interval.muteRefCount)
			resource.Metadata[model.MetadataTimeIntervalActiveRefCount] = strconv.Itoa(interval.activeRefCount)
			resourcesByID[resource.ID] = resource
			if interval.muteRefCount+interval.activeRefCount > 0 {
				relationships = append(relationships, alertmanagerRelationship(policy.ID, resource.ID, model.RelationshipUses, now))
			}
		}
	}
	for _, inhibitionRule := range alertmanagerInhibitionRules(config) {
		resource := alertmanagerResource(model.ResourceTypeInhibitionRule, inhibitionRule.name, instance, inhibitionRule.externalID, now)
		applyInhibitionRuleMetadata(&resource, inhibitionRule)
		resourcesByID[resource.ID] = resource
	}
	for _, silence := range silences {
		resource := alertmanagerSilenceResource(silence, instance, now)
		resourcesByID[resource.ID] = resource
	}

	for _, alert := range alerts {
		alertResource := alertmanagerAlertResource(alert, instance, now)
		resourcesByID[alertResource.ID] = alertResource
		for _, silenceID := range alert.Status.SilencedBy {
			silenceID = strings.TrimSpace(silenceID)
			if silenceID == "" {
				continue
			}
			silence := alertmanagerSilenceResource(alertmanagerSilence{ID: silenceID}, instance, now)
			if _, ok := resourcesByID[silence.ID]; !ok {
				silence.Metadata[model.MetadataSilenceState] = "unknown"
				resourcesByID[silence.ID] = silence
			}
			relationships = append(relationships, alertmanagerRelationship(alertResource.ID, silence.ID, model.RelationshipReferences, now))
		}
		for _, receiverName := range alertReceiverNames(alert.Receivers) {
			receiver := alertmanagerReceiverResource(receiverName, instance, now)
			receiver.Metadata["seen_in_alerts"] = "true"
			if existing, ok := resourcesByID[receiver.ID]; ok {
				if existing.Metadata == nil {
					existing.Metadata = map[string]string{}
				}
				if integrations := receiverIntegrations[receiverName]; len(integrations) > 0 && existing.Metadata[model.MetadataReceiverIntegrations] == "" {
					existing.Metadata[model.MetadataReceiverIntegrations] = strings.Join(integrations, ",")
				}
				existing.Metadata["seen_in_alerts"] = "true"
				resourcesByID[receiver.ID] = existing
			} else {
				resourcesByID[receiver.ID] = receiver
			}
			relationships = append(relationships, alertmanagerRelationship(alertResource.ID, receiver.ID, model.RelationshipUses, now))
		}

		alertName := strings.TrimSpace(alert.Labels["alertname"])
		if alertName == "" {
			continue
		}
		rule := alertmanagerResource(model.ResourceTypeAlertRule, alertName, instance, "rule:"+alertName, now)
		rule.Labels = cloneLabels(alert.Labels)
		mergeResourceLabels(resourcesByID, rule)
		relationships = append(relationships, alertmanagerRelationship(alertResource.ID, rule.ID, model.RelationshipReferences, now))
	}

	resources := make([]model.Resource, 0, len(resourcesByID))
	for _, resource := range resourcesByID {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ID < resources[j].ID
	})
	return Snapshot{Resources: resources, Relationships: relationships}
}

func alertmanagerRuntimeResource(status alertmanagerStatus, instance string, now time.Time) model.Resource {
	resource := alertmanagerResource(model.ResourceTypeInstance, "Alertmanager Runtime", instance, "runtime", now)
	clusterStatus := strings.ToLower(strings.TrimSpace(status.Cluster.Status))
	resource.Metadata = map[string]string{
		model.MetadataAlertmanagerRuntime:          "true",
		model.MetadataAlertmanagerClusterStatus:    clusterStatus,
		model.MetadataAlertmanagerClusterEnabled:   strconv.FormatBool(clusterStatus != "disabled"),
		model.MetadataAlertmanagerClusterPeerCount: strconv.Itoa(len(status.Cluster.Peers)),
	}
	if version := strings.TrimSpace(status.VersionInfo.Version); version != "" {
		resource.Metadata[model.MetadataAlertmanagerVersion] = version
	}
	if !status.Uptime.IsZero() {
		resource.Metadata[model.MetadataAlertmanagerStartedAt] = status.Uptime.UTC().Format(time.RFC3339)
	}
	return resource
}

func alertmanagerSilenceResource(silence alertmanagerSilence, instance string, now time.Time) model.Resource {
	silenceID := strings.TrimSpace(silence.ID)
	if silenceID == "" {
		silenceID = model.StableID("silence", instance, silence.CreatedBy, silence.Comment, silence.StartsAt.Format(time.RFC3339), silence.EndsAt.Format(time.RFC3339))
	}
	name := silenceID
	if matchers := alertmanagerSilenceMatchers(silence.Matchers); len(matchers) > 0 {
		name = strings.Join(matchers, ",")
	}
	resource := alertmanagerResource(model.ResourceTypeSilence, name, instance, "silence:"+silenceID, now)
	resource.Metadata[model.MetadataSilenceID] = silenceID
	if silence.Status.State != "" {
		resource.Metadata[model.MetadataSilenceState] = silence.Status.State
	}
	if !silence.StartsAt.IsZero() {
		resource.Metadata[model.MetadataStartsAt] = silence.StartsAt.Format(time.RFC3339)
	}
	if !silence.EndsAt.IsZero() {
		resource.Metadata[model.MetadataEndsAt] = silence.EndsAt.Format(time.RFC3339)
	}
	if !silence.UpdatedAt.IsZero() {
		resource.Metadata[model.MetadataUpdatedAt] = silence.UpdatedAt.Format(time.RFC3339)
	}
	if silence.CreatedBy != "" {
		resource.Metadata[model.MetadataSilenceCreatedBy] = silence.CreatedBy
	}
	if silence.Comment != "" {
		resource.Metadata[model.MetadataSilenceComment] = silence.Comment
	}
	if matchers := alertmanagerSilenceMatchers(silence.Matchers); len(matchers) > 0 {
		resource.Metadata[model.MetadataSilenceMatchers] = strings.Join(matchers, ",")
	}
	matcherDetails, positiveCount, negativeCount, regexCount := alertmanagerSilenceMatcherMetadata(silence.Matchers)
	resource.Metadata[model.MetadataSilenceMatcherCount] = strconv.Itoa(len(matcherDetails))
	resource.Metadata[model.MetadataSilencePositiveCount] = strconv.Itoa(positiveCount)
	resource.Metadata[model.MetadataSilenceNegativeCount] = strconv.Itoa(negativeCount)
	resource.Metadata[model.MetadataSilenceRegexCount] = strconv.Itoa(regexCount)
	if len(matcherDetails) > 0 {
		if encoded, err := json.Marshal(matcherDetails); err == nil {
			resource.Metadata[model.MetadataSilenceMatcherDetails] = string(encoded)
		}
	}
	if strings.EqualFold(silence.Status.State, "expired") {
		resource.Status = model.ResourceStatusDeprecated
	}
	return resource
}

type alertmanagerSilenceMatcherMetadataItem struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"is_regex"`
	IsEqual bool   `json:"is_equal"`
}

func alertmanagerSilenceMatcherMetadata(matchers []alertmanagerMatcher) ([]alertmanagerSilenceMatcherMetadataItem, int, int, int) {
	items := make([]alertmanagerSilenceMatcherMetadataItem, 0, len(matchers))
	positiveCount := 0
	negativeCount := 0
	regexCount := 0
	for _, matcher := range matchers {
		name := strings.TrimSpace(matcher.Name)
		if name == "" {
			continue
		}
		item := alertmanagerSilenceMatcherMetadataItem{Name: name, Value: strings.TrimSpace(matcher.Value), IsRegex: matcher.IsRegex, IsEqual: matcher.IsEqual}
		items = append(items, item)
		if item.IsEqual {
			positiveCount++
		} else {
			negativeCount++
		}
		if item.IsRegex {
			regexCount++
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name == items[j].Name {
			return items[i].Value < items[j].Value
		}
		return items[i].Name < items[j].Name
	})
	return items, positiveCount, negativeCount, regexCount
}

func alertmanagerSilenceMatchers(matchers []alertmanagerMatcher) []string {
	values := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		name := strings.TrimSpace(matcher.Name)
		if name == "" {
			continue
		}
		operator := "="
		if matcher.IsRegex {
			operator = "=~"
		}
		if !matcher.IsEqual {
			operator = "!="
			if matcher.IsRegex {
				operator = "!~"
			}
		}
		values = append(values, name+operator+strings.TrimSpace(matcher.Value))
	}
	sort.Strings(values)
	return values
}

func alertmanagerReceiverResource(name string, instance string, now time.Time) model.Resource {
	resource := alertmanagerResource(model.ResourceTypeReceiver, name, instance, "receiver:"+name, now)
	resource.Metadata["receiver_name"] = name
	return resource
}

func alertmanagerAlertResource(alert alertmanagerAlert, instance string, now time.Time) model.Resource {
	alertName := strings.TrimSpace(alert.Labels["alertname"])
	if alertName == "" {
		alertName = "alert"
	}
	fingerprint := strings.TrimSpace(alert.Fingerprint)
	if fingerprint == "" {
		fingerprint = alertFingerprint(alert.Labels)
	}
	resource := alertmanagerResource(model.ResourceTypeAlert, alertName, instance, "alert:"+fingerprint, now)
	resource.Labels = cloneLabels(alert.Labels)
	resource.Metadata = map[string]string{
		model.MetadataAlertState:   alert.Status.State,
		model.MetadataGeneratorURL: alert.GeneratorURL,
		model.MetadataFingerprint:  fingerprint,
	}
	if !alert.StartsAt.IsZero() {
		resource.Metadata[model.MetadataStartsAt] = alert.StartsAt.Format(time.RFC3339)
	}
	if !alert.EndsAt.IsZero() {
		resource.Metadata[model.MetadataEndsAt] = alert.EndsAt.Format(time.RFC3339)
	}
	if !alert.UpdatedAt.IsZero() {
		resource.Metadata[model.MetadataUpdatedAt] = alert.UpdatedAt.Format(time.RFC3339)
	}
	if receivers := alertReceiverNames(alert.Receivers); len(receivers) > 0 {
		resource.Metadata[model.MetadataReceiverNames] = strings.Join(receivers, ",")
	}
	if len(alert.Status.SilencedBy) > 0 {
		resource.Metadata[model.MetadataSilencedBy] = strings.Join(alert.Status.SilencedBy, ",")
	}
	if len(alert.Status.InhibitedBy) > 0 {
		resource.Metadata[model.MetadataInhibitedBy] = strings.Join(alert.Status.InhibitedBy, ",")
	}
	for key, value := range alert.Annotations {
		if key == "" || value == "" {
			continue
		}
		resource.Metadata["annotation."+key] = value
	}
	if strings.EqualFold(alert.Status.State, "suppressed") {
		resource.Status = model.ResourceStatusDeprecated
	}
	return resource
}

func alertReceiverNames(receivers []alertmanagerAlertReceiver) []string {
	names := make([]string, 0, len(receivers))
	seen := map[string]bool{}
	for _, receiver := range receivers {
		name := strings.TrimSpace(receiver.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func alertmanagerConfigReceivers(config string) (map[string]bool, map[string]bool, map[string][]string) {
	declared := map[string]bool{}
	routed := map[string]bool{}
	integrations := map[string][]string{}
	inReceivers := false
	currentReceiver := ""
	for _, line := range strings.Split(config, "\n") {
		trimmedRight := strings.TrimRight(line, " \t")
		trimmed := strings.TrimSpace(trimmedRight)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "-") {
			inReceivers = strings.TrimSuffix(trimmed, ":") == "receivers"
			if !inReceivers {
				currentReceiver = ""
			}
		}
		if inReceivers && strings.HasPrefix(trimmed, "- name:") {
			if name := trimYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:"))); name != "" {
				declared[name] = true
				currentReceiver = name
			}
			continue
		}
		if inReceivers && currentReceiver != "" {
			if integration := alertmanagerReceiverIntegration(trimmed); integration != "" {
				integrations[currentReceiver] = appendUniqueString(integrations[currentReceiver], integration)
				continue
			}
		}
		if strings.HasPrefix(trimmed, "receiver:") {
			if name := trimYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "receiver:"))); name != "" {
				routed[name] = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "- receiver:") {
			if name := trimYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- receiver:"))); name != "" {
				routed[name] = true
			}
		}
	}
	for receiver := range integrations {
		sort.Strings(integrations[receiver])
	}
	return declared, routed, integrations
}

func alertmanagerReceiverInsecureEndpointCounts(config string) map[string]int {
	var parsed struct {
		Receivers []map[string]any `yaml:"receivers"`
	}
	result := make(map[string]int)
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		return result
	}
	for _, receiver := range parsed.Receivers {
		name := strings.TrimSpace(fmt.Sprint(receiver["name"]))
		if name == "" {
			continue
		}
		seen := make(map[string]bool)
		collectInsecureEndpoints(receiver, "", seen)
		result[name] = len(seen)
	}
	return result
}

func insecureEndpointCount(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0
	}
	seen := make(map[string]bool)
	collectInsecureEndpoints(decoded, "", seen)
	return len(seen)
}

func collectInsecureEndpoints(value any, key string, seen map[string]bool) {
	switch typed := value.(type) {
	case string:
		if endpointSettingKey(key) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(typed)), "http://") {
			seen[strings.TrimSpace(typed)] = true
		}
	case []any:
		for _, item := range typed {
			collectInsecureEndpoints(item, key, seen)
		}
	case map[string]any:
		for childKey, item := range typed {
			collectInsecureEndpoints(item, childKey, seen)
		}
	}
}

func endpointSettingKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch normalized {
	case "url", "apiurl", "webhookurl", "endpoint", "endpointurl":
		return true
	default:
		return false
	}
}

type routingPolicyStats struct {
	defaultReceiver        string
	routeCount             int
	maxDepth               int
	continueRouteCount     int
	catchAllRouteCount     int
	shadowedRouteCount     int
	catchAllContinueCount  int
	timeIntervalRouteCount int
	invalidTimingCount     int
	roundedRepeatCount     int
	ungroupedRouteCount    int
}

type alertmanagerRoutingConfig struct {
	Route             *alertmanagerRoutingRoute  `yaml:"route"`
	InhibitRules      []alertmanagerInhibitRule  `yaml:"inhibit_rules"`
	MuteTimeIntervals []alertmanagerTimeInterval `yaml:"mute_time_intervals"`
	TimeIntervals     []alertmanagerTimeInterval `yaml:"time_intervals"`
}

type alertmanagerTimeInterval struct {
	Name          string           `yaml:"name"`
	TimeIntervals []map[string]any `yaml:"time_intervals"`
}

type alertmanagerTimeIntervalDetails struct {
	name           string
	declared       bool
	specCount      int
	muteRefCount   int
	activeRefCount int
}

type alertmanagerRoutingRoute struct {
	Receiver            string                     `yaml:"receiver"`
	Continue            bool                       `yaml:"continue"`
	Matchers            []string                   `yaml:"matchers"`
	Match               map[string]string          `yaml:"match"`
	MatchRE             map[string]string          `yaml:"match_re"`
	MuteTimeIntervals   []string                   `yaml:"mute_time_intervals"`
	ActiveTimeIntervals []string                   `yaml:"active_time_intervals"`
	GroupWait           string                     `yaml:"group_wait"`
	GroupInterval       string                     `yaml:"group_interval"`
	RepeatInterval      string                     `yaml:"repeat_interval"`
	GroupBy             []string                   `yaml:"group_by"`
	Routes              []alertmanagerRoutingRoute `yaml:"routes"`
}

type alertmanagerInhibitRule struct {
	SourceMatchers []string          `yaml:"source_matchers" json:"source_matchers"`
	TargetMatchers []string          `yaml:"target_matchers" json:"target_matchers"`
	SourceMatch    map[string]string `yaml:"source_match" json:"source_match"`
	SourceMatchRE  map[string]string `yaml:"source_match_re" json:"source_match_re"`
	TargetMatch    map[string]string `yaml:"target_match" json:"target_match"`
	TargetMatchRE  map[string]string `yaml:"target_match_re" json:"target_match_re"`
	Equal          []string          `yaml:"equal" json:"equal"`
}

type inhibitionRuleDetails struct {
	name               string
	externalID         string
	sourceMatcherCount int
	targetMatcherCount int
	equalLabelCount    int
	sourceRegexCount   int
	targetRegexCount   int
	sourceBroadCount   int
	targetBroadCount   int
}

func alertmanagerInhibitionRules(config string) []inhibitionRuleDetails {
	var parsed alertmanagerRoutingConfig
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		return nil
	}
	rules := make([]inhibitionRuleDetails, 0, len(parsed.InhibitRules))
	for _, rule := range parsed.InhibitRules {
		encoded, _ := json.Marshal(rule)
		hash := model.StableID("alertmanager-inhibition-rule", string(encoded))
		details := inhibitionRuleDetails{
			name:               "inhibition rule " + hash[:8],
			externalID:         "inhibition-rule:" + hash,
			sourceMatcherCount: len(rule.SourceMatchers) + len(rule.SourceMatch) + len(rule.SourceMatchRE),
			targetMatcherCount: len(rule.TargetMatchers) + len(rule.TargetMatch) + len(rule.TargetMatchRE),
			equalLabelCount:    uniqueNonEmptyStringCount(rule.Equal),
			sourceRegexCount:   matcherRegexCount(rule.SourceMatchers) + len(rule.SourceMatchRE),
			targetRegexCount:   matcherRegexCount(rule.TargetMatchers) + len(rule.TargetMatchRE),
			sourceBroadCount:   matcherBroadCount(rule.SourceMatchers) + broadRegexMapCount(rule.SourceMatchRE),
			targetBroadCount:   matcherBroadCount(rule.TargetMatchers) + broadRegexMapCount(rule.TargetMatchRE),
		}
		rules = append(rules, details)
	}
	return rules
}

func alertmanagerTimeIntervals(config string) []alertmanagerTimeIntervalDetails {
	var parsed alertmanagerRoutingConfig
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		return nil
	}
	byName := make(map[string]alertmanagerTimeIntervalDetails)
	for _, definition := range append(parsed.MuteTimeIntervals, parsed.TimeIntervals...) {
		name := strings.TrimSpace(definition.Name)
		if name == "" {
			continue
		}
		details := byName[name]
		details.name = name
		details.declared = true
		details.specCount += len(definition.TimeIntervals)
		byName[name] = details
	}
	if parsed.Route != nil {
		collectAlertmanagerTimeIntervalReferences(*parsed.Route, byName)
	}
	result := make([]alertmanagerTimeIntervalDetails, 0, len(byName))
	for _, details := range byName {
		result = append(result, details)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].name < result[j].name })
	return result
}

func collectAlertmanagerTimeIntervalReferences(route alertmanagerRoutingRoute, byName map[string]alertmanagerTimeIntervalDetails) {
	for _, name := range route.MuteTimeIntervals {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		details := byName[name]
		details.name = name
		details.muteRefCount++
		byName[name] = details
	}
	for _, name := range route.ActiveTimeIntervals {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		details := byName[name]
		details.name = name
		details.activeRefCount++
		byName[name] = details
	}
	for _, child := range route.Routes {
		collectAlertmanagerTimeIntervalReferences(child, byName)
	}
}

func uniqueNonEmptyStringCount(values []string) int {
	seen := make(map[string]bool)
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = true
		}
	}
	return len(seen)
}

func matcherRegexCount(matchers []string) int {
	count := 0
	for _, matcher := range matchers {
		operator, _ := matcherOperatorAndValue(matcher)
		if operator == "=~" || operator == "!~" {
			count++
		}
	}
	return count
}

func matcherBroadCount(matchers []string) int {
	count := 0
	for _, matcher := range matchers {
		operator, value := matcherOperatorAndValue(matcher)
		if operator == "=~" && broadRegex(value) {
			count++
		}
	}
	return count
}

func matcherOperatorAndValue(matcher string) (string, string) {
	matcher = strings.TrimSpace(matcher)
	for _, operator := range []string{"!~", "=~", "!=", "="} {
		if index := strings.Index(matcher, operator); index >= 0 {
			return operator, strings.TrimSpace(matcher[index+len(operator):])
		}
	}
	return "", ""
}

func broadRegex(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	switch value {
	case ".*", ".+", "^.*$", "^.+$":
		return true
	default:
		return false
	}
}

func broadRegexMapCount(values map[string]string) int {
	count := 0
	for _, value := range values {
		if broadRegex(value) {
			count++
		}
	}
	return count
}

func applyInhibitionRuleMetadata(resource *model.Resource, details inhibitionRuleDetails) {
	if resource.Metadata == nil {
		resource.Metadata = make(map[string]string)
	}
	resource.Metadata[model.MetadataInhibitionSourceMatcherCount] = strconv.Itoa(details.sourceMatcherCount)
	resource.Metadata[model.MetadataInhibitionTargetMatcherCount] = strconv.Itoa(details.targetMatcherCount)
	resource.Metadata[model.MetadataInhibitionEqualLabelCount] = strconv.Itoa(details.equalLabelCount)
	resource.Metadata[model.MetadataInhibitionSourceRegexCount] = strconv.Itoa(details.sourceRegexCount)
	resource.Metadata[model.MetadataInhibitionTargetRegexCount] = strconv.Itoa(details.targetRegexCount)
	resource.Metadata[model.MetadataInhibitionSourceBroadCount] = strconv.Itoa(details.sourceBroadCount)
	resource.Metadata[model.MetadataInhibitionTargetBroadCount] = strconv.Itoa(details.targetBroadCount)
}

func alertmanagerRoutingPolicyStats(config string) (routingPolicyStats, bool) {
	var parsed alertmanagerRoutingConfig
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil || parsed.Route == nil {
		return routingPolicyStats{}, false
	}
	stats := routingPolicyStats{defaultReceiver: strings.TrimSpace(parsed.Route.Receiver), maxDepth: 1}
	collectAlertmanagerRouteStats(*parsed.Route, 1, true, &stats)
	collectAlertmanagerTimingStats(*parsed.Route, defaultNotificationTiming(), &stats)
	return stats, true
}

type notificationTiming struct {
	groupWait, groupInterval, repeatInterval time.Duration
}

func defaultNotificationTiming() notificationTiming {
	return notificationTiming{groupWait: 30 * time.Second, groupInterval: 5 * time.Minute, repeatInterval: 4 * time.Hour}
}

func parseNotificationDuration(raw string) (time.Duration, bool) {
	parsed, err := prommodel.ParseDuration(strings.TrimSpace(raw))
	return time.Duration(parsed), err == nil && parsed > 0
}

func applyNotificationTiming(rawWait, rawGroup, rawRepeat string, inherited notificationTiming, stats *routingPolicyStats) notificationTiming {
	effective := inherited
	invalidGroupOrRepeat := false
	apply := func(raw string, target *time.Duration, affectsRelation bool) {
		if strings.TrimSpace(raw) == "" {
			return
		}
		parsed, ok := parseNotificationDuration(raw)
		if !ok {
			stats.invalidTimingCount++
			if affectsRelation {
				invalidGroupOrRepeat = true
			}
			return
		}
		*target = parsed
	}
	apply(rawWait, &effective.groupWait, false)
	apply(rawGroup, &effective.groupInterval, true)
	apply(rawRepeat, &effective.repeatInterval, true)
	hasExplicitRelationSetting := strings.TrimSpace(rawGroup) != "" || strings.TrimSpace(rawRepeat) != ""
	if invalidGroupOrRepeat || !hasExplicitRelationSetting {
		return effective
	}
	if effective.repeatInterval < effective.groupInterval {
		stats.invalidTimingCount++
	} else if effective.groupInterval > 0 && effective.repeatInterval%effective.groupInterval != 0 {
		stats.roundedRepeatCount++
	}
	return effective
}

func collectAlertmanagerTimingStats(route alertmanagerRoutingRoute, inherited notificationTiming, stats *routingPolicyStats) {
	effective := applyNotificationTiming(route.GroupWait, route.GroupInterval, route.RepeatInterval, inherited, stats)
	for _, child := range route.Routes {
		collectAlertmanagerTimingStats(child, effective, stats)
	}
}

func collectAlertmanagerRouteStats(route alertmanagerRoutingRoute, depth int, root bool, stats *routingPolicyStats) {
	stats.routeCount++
	if depth > stats.maxDepth {
		stats.maxDepth = depth
	}
	if route.Continue {
		stats.continueRouteCount++
	}
	if len(route.MuteTimeIntervals) > 0 || len(route.ActiveTimeIntervals) > 0 {
		stats.timeIntervalRouteCount++
	}
	if notificationGroupingDisabled(route.GroupBy) {
		stats.ungroupedRouteCount++
	}
	if !root && alertmanagerRouteMatcherCount(route) == 0 {
		stats.catchAllRouteCount++
		if route.Continue {
			stats.catchAllContinueCount++
		}
	}
	for index, child := range route.Routes {
		if alertmanagerRouteMatcherCount(child) == 0 && !child.Continue && index < len(route.Routes)-1 {
			for _, shadowed := range route.Routes[index+1:] {
				stats.shadowedRouteCount += alertmanagerRouteTreeSize(shadowed)
			}
			break
		}
	}
	for _, child := range route.Routes {
		collectAlertmanagerRouteStats(child, depth+1, false, stats)
	}
}

func alertmanagerRouteMatcherCount(route alertmanagerRoutingRoute) int {
	return len(route.Matchers) + len(route.Match) + len(route.MatchRE)
}

func notificationGroupingDisabled(groupBy []string) bool {
	for _, label := range groupBy {
		if strings.TrimSpace(label) == "..." {
			return true
		}
	}
	return false
}

func alertmanagerRouteTreeSize(route alertmanagerRoutingRoute) int {
	size := 1
	for _, child := range route.Routes {
		size += alertmanagerRouteTreeSize(child)
	}
	return size
}

func applyRoutingPolicyMetadata(resource *model.Resource, stats routingPolicyStats) {
	if resource.Metadata == nil {
		resource.Metadata = make(map[string]string)
	}
	resource.Metadata[model.MetadataPolicyDefaultReceiver] = stats.defaultReceiver
	resource.Metadata[model.MetadataPolicyRouteCount] = strconv.Itoa(stats.routeCount)
	resource.Metadata[model.MetadataPolicyMaxDepth] = strconv.Itoa(stats.maxDepth)
	resource.Metadata[model.MetadataPolicyContinueRouteCount] = strconv.Itoa(stats.continueRouteCount)
	resource.Metadata[model.MetadataPolicyCatchAllRouteCount] = strconv.Itoa(stats.catchAllRouteCount)
	resource.Metadata[model.MetadataPolicyShadowedRouteCount] = strconv.Itoa(stats.shadowedRouteCount)
	resource.Metadata[model.MetadataPolicyCatchAllContinueCount] = strconv.Itoa(stats.catchAllContinueCount)
	resource.Metadata[model.MetadataPolicyTimeIntervalRouteCount] = strconv.Itoa(stats.timeIntervalRouteCount)
	resource.Metadata[model.MetadataPolicyInvalidTimingCount] = strconv.Itoa(stats.invalidTimingCount)
	resource.Metadata[model.MetadataPolicyRoundedRepeatCount] = strconv.Itoa(stats.roundedRepeatCount)
	resource.Metadata[model.MetadataPolicyUngroupedRouteCount] = strconv.Itoa(stats.ungroupedRouteCount)
}

func alertmanagerReceiverIntegration(trimmed string) string {
	key := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
	if !strings.HasSuffix(key, ":") {
		return ""
	}
	key = strings.TrimSuffix(key, ":")
	if strings.HasSuffix(key, "_configs") {
		return strings.TrimSuffix(key, "_configs")
	}
	if strings.HasSuffix(key, "_config") {
		return strings.TrimSuffix(key, "_config")
	}
	return ""
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func trimYAMLScalar(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if index := strings.Index(value, " #"); index >= 0 {
		value = strings.TrimSpace(value[:index])
	}
	value = strings.Trim(value, `"'`)
	return strings.TrimSpace(value)
}

func alertmanagerResource(resourceType model.ResourceType, name string, instance string, externalID string, now time.Time) model.Resource {
	uid := model.StableID(string(resourceType), alertmanagerSystem, instance, externalID)
	return model.Resource{
		ID:        uid,
		Type:      resourceType,
		Name:      name,
		UID:       uid,
		Source:    model.SourceInfo{System: alertmanagerSystem, Instance: instance, ExternalID: externalID},
		Metadata:  map[string]string{},
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
}

func alertmanagerRelationship(fromID, toID string, relationshipType model.RelationshipType, now time.Time) model.Relationship {
	return model.Relationship{
		ID:        model.StableID(fromID, string(relationshipType), toID),
		FromID:    fromID,
		ToID:      toID,
		Type:      relationshipType,
		CreatedAt: now,
	}
}

func alertFingerprint(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}
