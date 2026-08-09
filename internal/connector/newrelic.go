package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/queryparse"
)

const (
	newRelicSystem             = "newrelic"
	maxNewRelicEntityCount     = 50000
	maxNewRelicPolicyCount     = 10000
	maxNewRelicConditionCount  = 50000
	maxNewRelicResponseSize    = 16 << 20
	maxNewRelicPaginationPages = 10000
)

const newRelicEntityQuery = `query MoniCheckEntities($query: String!, $cursor: String) {
  actor {
    entitySearch(query: $query) {
      results(cursor: $cursor) {
        nextCursor
        entities {
          guid
          name
          accountId
          domain
          type
          reporting
          tags {
            key
            values
          }
          ... on AlertableEntityOutline {
            alertSeverity
          }
        }
      }
    }
  }
}`

const newRelicPolicyQuery = `query MoniCheckPolicies($accountId: Int!, $cursor: String) {
  actor {
    account(id: $accountId) {
      alerts {
        policiesSearch(cursor: $cursor) {
          nextCursor
          policies {
            id
            name
            incidentPreference
          }
        }
      }
    }
  }
}`

const newRelicConditionQuery = `query MoniCheckConditions($accountId: Int!, $cursor: String) {
  actor {
    account(id: $accountId) {
      alerts {
        nrqlConditionsSearch(cursor: $cursor) {
          nextCursor
          nrqlConditions {
            id
            name
            description
            titleTemplate
            enabled
            policyId
            runbookUrl
            type
            ... on AlertsNrqlBaselineCondition {
              baselineDirection
            }
            ... on AlertsNrqlStaticCondition {
              valueFunction
            }
            violationTimeLimitSeconds
            nrql {
              query
            }
            signal {
              aggregationWindow
              aggregationMethod
              aggregationDelay
              aggregationTimer
              evaluationDelay
              fillOption
              fillValue
              slideBy
            }
            expiration {
              expirationDuration
              closeViolationsOnExpiration
              openViolationOnExpiration
            }
            terms {
              operator
              threshold
              thresholdDuration
              priority
              thresholdOccurrences
            }
          }
        }
      }
    }
  }
}`

type NewRelicConnector struct {
	endpoint  string
	accountID int
	client    *http.Client
}

type newRelicTag struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

type newRelicEntity struct {
	GUID          string        `json:"guid"`
	Name          string        `json:"name"`
	AccountID     int           `json:"accountId"`
	Domain        string        `json:"domain"`
	Type          string        `json:"type"`
	Reporting     *bool         `json:"reporting"`
	AlertSeverity *string       `json:"alertSeverity"`
	Tags          []newRelicTag `json:"tags"`
}

type newRelicPolicy struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	IncidentPreference string `json:"incidentPreference"`
}

type newRelicCondition struct {
	ID                        string `json:"id"`
	Name                      string `json:"name"`
	Description               string `json:"description"`
	TitleTemplate             string `json:"titleTemplate"`
	Enabled                   bool   `json:"enabled"`
	PolicyID                  string `json:"policyId"`
	RunbookURL                string `json:"runbookUrl"`
	Type                      string `json:"type"`
	BaselineDirection         string `json:"baselineDirection"`
	ValueFunction             string `json:"valueFunction"`
	ViolationTimeLimitSeconds int    `json:"violationTimeLimitSeconds"`
	NRQL                      struct {
		Query string `json:"query"`
	} `json:"nrql"`
	Signal struct {
		AggregationWindow int      `json:"aggregationWindow"`
		AggregationMethod string   `json:"aggregationMethod"`
		AggregationDelay  int      `json:"aggregationDelay"`
		AggregationTimer  int      `json:"aggregationTimer"`
		EvaluationDelay   *int     `json:"evaluationDelay"`
		FillOption        string   `json:"fillOption"`
		FillValue         *float64 `json:"fillValue"`
		SlideBy           *int     `json:"slideBy"`
	} `json:"signal"`
	Expiration *struct {
		ExpirationDuration          *int  `json:"expirationDuration"`
		CloseViolationsOnExpiration *bool `json:"closeViolationsOnExpiration"`
		OpenViolationOnExpiration   *bool `json:"openViolationOnExpiration"`
	} `json:"expiration"`
	Terms []struct {
		Operator             string   `json:"operator"`
		Threshold            *float64 `json:"threshold"`
		ThresholdDuration    int      `json:"thresholdDuration"`
		Priority             string   `json:"priority"`
		ThresholdOccurrences string   `json:"thresholdOccurrences"`
	} `json:"terms"`
}

func NewNewRelicConnectorWithOptions(endpoint string, accountID int, options HTTPOptions) (*NewRelicConnector, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("new relic graphql url is empty")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid new relic graphql url %q", endpoint)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("new relic graphql url must not contain userinfo")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("new relic graphql url must use http or https")
	}
	if accountID <= 0 {
		return nil, fmt.Errorf("new relic account id must be positive")
	}
	if options.Timeout <= 0 {
		options.Timeout = 20 * time.Second
	}
	client, err := NewHTTPClient(options)
	if err != nil {
		return nil, err
	}
	return &NewRelicConnector{endpoint: endpoint, accountID: accountID, client: client}, nil
}

func (c *NewRelicConnector) ID() string   { return newRelicSystem }
func (c *NewRelicConnector) Name() string { return "New Relic Connector" }

func (c *NewRelicConnector) Sync(ctx context.Context) (Snapshot, error) {
	entities, entityTruncated, err := c.fetchEntities(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if entityTruncated {
		return Snapshot{}, fmt.Errorf("new relic entity discovery exceeded the %d-resource safety limit", maxNewRelicEntityCount)
	}

	policies, policyTruncated, policyErr := c.fetchPolicies(ctx)
	conditions, conditionTruncated, conditionErr := c.fetchConditions(ctx)
	now := time.Now().UTC()
	resources := make([]model.Resource, 0, len(entities)+len(conditions))
	policyByID := make(map[string]newRelicPolicy, len(policies))
	for _, policy := range policies {
		policyByID[policy.ID] = policy
	}
	for _, entity := range entities {
		if resource, ok := c.entityResource(entity, now); ok {
			resources = append(resources, resource)
		}
	}
	for _, condition := range conditions {
		resources = append(resources, c.conditionResource(condition, policyByID[condition.PolicyID], now))
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })

	diagnostics := []model.Diagnostic{
		newRelicOptionalDiagnostic("newrelic_alert_policies", "New Relic alert policy discovery", len(policies), policyTruncated, policyErr),
		newRelicOptionalDiagnostic("newrelic_nrql_conditions", "New Relic NRQL condition discovery", len(conditions), conditionTruncated, conditionErr),
	}
	return Snapshot{
		Resources:   resources,
		Diagnostics: diagnostics,
		Partial:     policyErr != nil || conditionErr != nil || policyTruncated || conditionTruncated,
	}, nil
}

func (c *NewRelicConnector) fetchEntities(ctx context.Context) ([]newRelicEntity, bool, error) {
	query := fmt.Sprintf("accountId = %d AND type IN ('APPLICATION', 'SERVICE')", c.accountID)
	items := make([]newRelicEntity, 0)
	cursor := ""
	for page := 0; page < maxNewRelicPaginationPages; page++ {
		var data struct {
			Actor struct {
				EntitySearch struct {
					Results struct {
						NextCursor string           `json:"nextCursor"`
						Entities   []newRelicEntity `json:"entities"`
					} `json:"results"`
				} `json:"entitySearch"`
			} `json:"actor"`
		}
		if err := c.graphql(ctx, "entity discovery", newRelicEntityQuery, map[string]any{
			"query": query, "cursor": nullableCursor(cursor),
		}, &data); err != nil {
			return nil, false, fmt.Errorf("new relic entity discovery: %w", err)
		}
		result := data.Actor.EntitySearch.Results
		items = append(items, result.Entities...)
		if len(items) > maxNewRelicEntityCount {
			return items[:maxNewRelicEntityCount], true, nil
		}
		if strings.TrimSpace(result.NextCursor) == "" {
			return items, false, nil
		}
		if result.NextCursor == cursor {
			return nil, false, fmt.Errorf("new relic entity discovery cursor did not advance")
		}
		cursor = result.NextCursor
	}
	return nil, false, fmt.Errorf("new relic entity discovery exceeded pagination safety limit")
}

func (c *NewRelicConnector) fetchPolicies(ctx context.Context) ([]newRelicPolicy, bool, error) {
	items := make([]newRelicPolicy, 0)
	cursor := ""
	for page := 0; page < maxNewRelicPaginationPages; page++ {
		var data struct {
			Actor struct {
				Account struct {
					Alerts struct {
						Search struct {
							NextCursor string           `json:"nextCursor"`
							Policies   []newRelicPolicy `json:"policies"`
						} `json:"policiesSearch"`
					} `json:"alerts"`
				} `json:"account"`
			} `json:"actor"`
		}
		if err := c.graphql(ctx, "alert policy discovery", newRelicPolicyQuery, map[string]any{
			"accountId": c.accountID, "cursor": nullableCursor(cursor),
		}, &data); err != nil {
			return nil, false, err
		}
		result := data.Actor.Account.Alerts.Search
		items = append(items, result.Policies...)
		if len(items) > maxNewRelicPolicyCount {
			return items[:maxNewRelicPolicyCount], true, nil
		}
		if strings.TrimSpace(result.NextCursor) == "" {
			return items, false, nil
		}
		if result.NextCursor == cursor {
			return nil, false, fmt.Errorf("new relic alert policy cursor did not advance")
		}
		cursor = result.NextCursor
	}
	return nil, false, fmt.Errorf("new relic alert policy discovery exceeded pagination safety limit")
}

func (c *NewRelicConnector) fetchConditions(ctx context.Context) ([]newRelicCondition, bool, error) {
	items := make([]newRelicCondition, 0)
	cursor := ""
	for page := 0; page < maxNewRelicPaginationPages; page++ {
		var data struct {
			Actor struct {
				Account struct {
					Alerts struct {
						Search struct {
							NextCursor string              `json:"nextCursor"`
							Conditions []newRelicCondition `json:"nrqlConditions"`
						} `json:"nrqlConditionsSearch"`
					} `json:"alerts"`
				} `json:"account"`
			} `json:"actor"`
		}
		if err := c.graphql(ctx, "NRQL condition discovery", newRelicConditionQuery, map[string]any{
			"accountId": c.accountID, "cursor": nullableCursor(cursor),
		}, &data); err != nil {
			return nil, false, err
		}
		result := data.Actor.Account.Alerts.Search
		items = append(items, result.Conditions...)
		if len(items) > maxNewRelicConditionCount {
			return items[:maxNewRelicConditionCount], true, nil
		}
		if strings.TrimSpace(result.NextCursor) == "" {
			return items, false, nil
		}
		if result.NextCursor == cursor {
			return nil, false, fmt.Errorf("new relic NRQL condition cursor did not advance")
		}
		cursor = result.NextCursor
	}
	return nil, false, fmt.Errorf("new relic NRQL condition discovery exceeded pagination safety limit")
}

func nullableCursor(cursor string) any {
	if cursor == "" {
		return nil
	}
	return cursor
}

func (c *NewRelicConnector) graphql(ctx context.Context, operation, query string, variables map[string]any, target any) error {
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request = markRequestIdempotent(request)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("new relic %s request: %w", operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return fmt.Errorf("new relic %s returned status %d", operation, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxNewRelicResponseSize+1))
	if err != nil {
		return fmt.Errorf("read new relic %s response: %w", operation, err)
	}
	if len(data) > maxNewRelicResponseSize {
		return fmt.Errorf("new relic %s response exceeds %d bytes", operation, maxNewRelicResponseSize)
	}
	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode new relic %s response: %w", operation, err)
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("new relic %s returned %d graphql errors", operation, len(envelope.Errors))
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return fmt.Errorf("new relic %s returned no data", operation)
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return fmt.Errorf("decode new relic %s data: %w", operation, err)
	}
	return nil
}

func (c *NewRelicConnector) entityResource(entity newRelicEntity, now time.Time) (model.Resource, bool) {
	guid := strings.TrimSpace(entity.GUID)
	name := strings.TrimSpace(entity.Name)
	if guid == "" || name == "" {
		return model.Resource{}, false
	}
	externalID := "entity:" + model.StableID("newrelic-entity", guid)
	labels := newRelicGovernanceTags(entity.Tags)
	metadata := map[string]string{
		model.MetadataNewRelicEntity:                 "true",
		model.MetadataNewRelicEntityDomain:           strings.TrimSpace(entity.Domain),
		model.MetadataNewRelicEntityType:             strings.TrimSpace(entity.Type),
		model.MetadataNewRelicReportingDeclared:      strconv.FormatBool(entity.Reporting != nil),
		model.MetadataNewRelicAlertSeverityDeclared:  strconv.FormatBool(entity.AlertSeverity != nil),
		model.MetadataNewRelicOwnershipDeclared:      strconv.FormatBool(labels[model.MetadataOwner] != "" || labels["team"] != ""),
		model.MetadataNewRelicAllowlistedTagKeyCount: strconv.Itoa(len(labels)),
	}
	if entity.Reporting != nil {
		metadata[model.MetadataNewRelicReporting] = strconv.FormatBool(*entity.Reporting)
	}
	if entity.AlertSeverity != nil {
		metadata[model.MetadataNewRelicAlertSeverity] = strings.ToUpper(strings.TrimSpace(*entity.AlertSeverity))
	}
	return model.Resource{
		ID:   model.StableID(newRelicSystem, externalID),
		Type: model.ResourceTypeService,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     newRelicSystem,
			Instance:   model.StableID("newrelic-account", strconv.Itoa(c.accountID)),
			ExternalID: externalID,
		},
		Metadata:  metadata,
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}, true
}

func (c *NewRelicConnector) conditionResource(condition newRelicCondition, policy newRelicPolicy, now time.Time) model.Resource {
	conditionFingerprint := model.StableID("newrelic-condition", strings.TrimSpace(condition.ID))
	name := strings.TrimSpace(condition.Name)
	if name == "" {
		name = "New Relic NRQL condition"
	}
	criticalTerms := 0
	warningTerms := 0
	criticalAtLeastOnceTerms := 0
	invalidThresholdOperatorCount := 0
	invalidThresholdOccurrenceCount := 0
	invalidThresholdValueCount := 0
	maxDuration := 0
	criticalMinDuration := -1
	criticalMaxDuration := 0
	invalidCriticalDurationCount := 0
	for _, term := range condition.Terms {
		if !newRelicThresholdOperatorValid(term.Operator) {
			invalidThresholdOperatorCount++
		}
		if !newRelicThresholdOccurrenceValid(term.ThresholdOccurrences) {
			invalidThresholdOccurrenceCount++
		}
		if newRelicThresholdValueInvalid(term.Threshold) {
			invalidThresholdValueCount++
		}
		switch strings.ToUpper(strings.TrimSpace(term.Priority)) {
		case "CRITICAL":
			criticalTerms++
			if strings.EqualFold(strings.TrimSpace(term.ThresholdOccurrences), "AT_LEAST_ONCE") {
				criticalAtLeastOnceTerms++
			}
			if criticalMinDuration < 0 || term.ThresholdDuration < criticalMinDuration {
				criticalMinDuration = term.ThresholdDuration
			}
			if term.ThresholdDuration > criticalMaxDuration {
				criticalMaxDuration = term.ThresholdDuration
			}
			if term.ThresholdDuration < 30 || term.ThresholdDuration > 2*60*60 {
				invalidCriticalDurationCount++
			}
		case "WARNING":
			warningTerms++
		}
		if term.ThresholdDuration > maxDuration {
			maxDuration = term.ThresholdDuration
		}
	}
	if criticalMinDuration < 0 {
		criticalMinDuration = 0
	}
	thresholdPriorityCountInvalid := newRelicThresholdPriorityCountInvalid(len(condition.Terms), criticalTerms, warningTerms)
	invalidBaselineThresholdDurationCount := newRelicInvalidBaselineThresholdDurationCount(condition)
	baselineDirectionEvaluable, baselineDirectionInvalid := newRelicBaselineDirectionValidity(condition)
	staticValueFunctionEvaluable, staticValueFunctionInvalid := newRelicStaticValueFunctionValidity(condition)
	queryScopeEvaluable, queryScopeClausePresent := newRelicQueryScope(condition.NRQL.Query)
	queryCompatibilityEvaluable, queryIncompatibleClauseCount := newRelicQueryAlertCompatibility(condition.NRQL.Query)
	aggregationDelayEvaluable, aggregationDelayInvalid := newRelicAggregationDelayValidity(condition)
	eventTimerWindowEvaluable, eventTimerShorterThanWindow := newRelicEventTimerWindowOrder(condition)
	slideByDeclared, slidingWindowEvaluable, slidingWindowInvalid, slidingWindowOverlapFactor := newRelicSlidingWindowValidity(condition)
	evaluationDelayDeclared, evaluationDelaySeconds, evaluationDelayInvalid := newRelicEvaluationDelay(condition)
	gapFillOption, gapFillOptionEvaluable, gapFillOptionInvalid := newRelicGapFillOptionValidity(condition)
	staticGapFillValueEvaluable, staticGapFillValueInvalid := newRelicStaticGapFillValueValidity(condition)
	staticGapFillEvaluable, staticGapFillCriticalBreachCount := newRelicStaticGapFillCriticalBreaches(condition)
	lossOfSignalCloseEvaluable, lossOfSignalCloseConfigured := newRelicLossOfSignalCloseAction(condition)
	slideBySeconds := 0
	if condition.Signal.SlideBy != nil {
		slideBySeconds = *condition.Signal.SlideBy
	}
	metadata := map[string]string{
		model.MetadataNewRelicNRQLCondition:           "true",
		model.MetadataEnabled:                         strconv.FormatBool(condition.Enabled),
		model.MetadataDisabled:                        strconv.FormatBool(!condition.Enabled),
		model.MetadataNewRelicConditionType:           strings.ToUpper(strings.TrimSpace(condition.Type)),
		model.MetadataNewRelicQueryLength:             strconv.Itoa(len(strings.TrimSpace(condition.NRQL.Query))),
		model.MetadataNewRelicQueryScopeEvaluable:     strconv.FormatBool(queryScopeEvaluable),
		model.MetadataNewRelicQueryScopeClausePresent: strconv.FormatBool(queryScopeClausePresent),
		model.MetadataNewRelicQueryCompatibilityEvaluable: strconv.FormatBool(
			queryCompatibilityEvaluable,
		),
		model.MetadataNewRelicQueryIncompatibleClauseCount: strconv.Itoa(
			queryIncompatibleClauseCount,
		),
		model.MetadataNewRelicDescriptionConfigured:   strconv.FormatBool(strings.TrimSpace(condition.Description) != ""),
		model.MetadataNewRelicTitleTemplateConfigured: strconv.FormatBool(strings.TrimSpace(condition.TitleTemplate) != ""),
		model.MetadataNewRelicRunbookConfigured:       strconv.FormatBool(strings.TrimSpace(condition.RunbookURL) != ""),
		model.MetadataNewRelicTermCount:               strconv.Itoa(len(condition.Terms)),
		model.MetadataNewRelicCriticalTermCount:       strconv.Itoa(criticalTerms),
		model.MetadataNewRelicWarningTermCount:        strconv.Itoa(warningTerms),
		model.MetadataNewRelicCriticalAtLeastOnceTermCount: strconv.Itoa(
			criticalAtLeastOnceTerms,
		),
		model.MetadataNewRelicThresholdPriorityCountInvalid: strconv.FormatBool(
			thresholdPriorityCountInvalid,
		),
		model.MetadataNewRelicInvalidThresholdOperatorCount: strconv.Itoa(
			invalidThresholdOperatorCount,
		),
		model.MetadataNewRelicInvalidThresholdOccurrenceCount: strconv.Itoa(
			invalidThresholdOccurrenceCount,
		),
		model.MetadataNewRelicInvalidThresholdValueCount: strconv.Itoa(
			invalidThresholdValueCount,
		),
		model.MetadataNewRelicMaxThresholdDuration: strconv.Itoa(maxDuration),
		model.MetadataNewRelicCriticalThresholdDurationMin: strconv.Itoa(
			criticalMinDuration,
		),
		model.MetadataNewRelicCriticalThresholdDurationMax: strconv.Itoa(
			criticalMaxDuration,
		),
		model.MetadataNewRelicInvalidCriticalThresholdDurationCount: strconv.Itoa(
			invalidCriticalDurationCount,
		),
		model.MetadataNewRelicInvalidBaselineThresholdDurationCount: strconv.Itoa(
			invalidBaselineThresholdDurationCount,
		),
		model.MetadataNewRelicBaselineDirectionEvaluable: strconv.FormatBool(
			baselineDirectionEvaluable,
		),
		model.MetadataNewRelicBaselineDirectionInvalid: strconv.FormatBool(
			baselineDirectionInvalid,
		),
		model.MetadataNewRelicStaticValueFunctionEvaluable: strconv.FormatBool(
			staticValueFunctionEvaluable,
		),
		model.MetadataNewRelicStaticValueFunctionInvalid: strconv.FormatBool(
			staticValueFunctionInvalid,
		),
		model.MetadataNewRelicAggregationWindow: strconv.Itoa(condition.Signal.AggregationWindow),
		model.MetadataNewRelicAggregationMethod: strings.ToUpper(strings.TrimSpace(condition.Signal.AggregationMethod)),
		model.MetadataNewRelicAggregationDelay:  strconv.Itoa(condition.Signal.AggregationDelay),
		model.MetadataNewRelicAggregationDelayEvaluable: strconv.FormatBool(
			aggregationDelayEvaluable,
		),
		model.MetadataNewRelicAggregationDelayInvalid: strconv.FormatBool(
			aggregationDelayInvalid,
		),
		model.MetadataNewRelicAggregationTimer:       strconv.Itoa(condition.Signal.AggregationTimer),
		model.MetadataNewRelicSlideByDeclared:        strconv.FormatBool(slideByDeclared),
		model.MetadataNewRelicSlideBySeconds:         strconv.Itoa(slideBySeconds),
		model.MetadataNewRelicSlidingWindowEvaluable: strconv.FormatBool(slidingWindowEvaluable),
		model.MetadataNewRelicSlidingWindowInvalid:   strconv.FormatBool(slidingWindowInvalid),
		model.MetadataNewRelicSlidingWindowOverlapFactor: strconv.Itoa(
			slidingWindowOverlapFactor,
		),
		model.MetadataNewRelicEventTimerWindowEvaluable: strconv.FormatBool(eventTimerWindowEvaluable),
		model.MetadataNewRelicEventTimerShorterThanWindow: strconv.FormatBool(
			eventTimerShorterThanWindow,
		),
		model.MetadataNewRelicEvaluationDelayDeclared: strconv.FormatBool(
			evaluationDelayDeclared,
		),
		model.MetadataNewRelicEvaluationDelaySeconds: strconv.Itoa(
			evaluationDelaySeconds,
		),
		model.MetadataNewRelicEvaluationDelayInvalid: strconv.FormatBool(
			evaluationDelayInvalid,
		),
		model.MetadataNewRelicGapFillOption:          gapFillOption,
		model.MetadataNewRelicGapFillOptionEvaluable: strconv.FormatBool(gapFillOptionEvaluable),
		model.MetadataNewRelicGapFillOptionInvalid:   strconv.FormatBool(gapFillOptionInvalid),
		model.MetadataNewRelicStaticGapFillValueEvaluable: strconv.FormatBool(
			staticGapFillValueEvaluable,
		),
		model.MetadataNewRelicStaticGapFillValueInvalid: strconv.FormatBool(
			staticGapFillValueInvalid,
		),
		model.MetadataNewRelicStaticGapFillEvaluable: strconv.FormatBool(staticGapFillEvaluable),
		model.MetadataNewRelicStaticGapFillCriticalBreachCount: strconv.Itoa(
			staticGapFillCriticalBreachCount,
		),
		model.MetadataNewRelicViolationTimeLimitSeconds: strconv.Itoa(condition.ViolationTimeLimitSeconds),
		model.MetadataNewRelicPolicyDeclared:            strconv.FormatBool(strings.TrimSpace(condition.PolicyID) != ""),
		model.MetadataNewRelicLossOfSignalEvaluable:     "true",
		model.MetadataNewRelicLossOfSignalConfigured:    strconv.FormatBool(newRelicLossOfSignalConfigured(condition)),
		model.MetadataNewRelicLossOfSignalDurationInvalid: strconv.FormatBool(
			newRelicLossOfSignalDurationInvalid(condition),
		),
		model.MetadataNewRelicLossOfSignalDurationShort: strconv.FormatBool(
			newRelicLossOfSignalDurationShort(condition),
		),
		model.MetadataNewRelicLossOfSignalCloseEvaluable:  strconv.FormatBool(lossOfSignalCloseEvaluable),
		model.MetadataNewRelicLossOfSignalCloseConfigured: strconv.FormatBool(lossOfSignalCloseConfigured),
	}
	if policy.ID != "" {
		metadata[model.MetadataNewRelicIncidentPreference] = strings.ToUpper(strings.TrimSpace(policy.IncidentPreference))
	}
	status := model.ResourceStatusActive
	if !condition.Enabled {
		status = model.ResourceStatusDeprecated
	}
	externalID := "condition:" + conditionFingerprint
	return model.Resource{
		ID:   model.StableID(newRelicSystem, externalID),
		Type: model.ResourceTypeAlertRule,
		Name: name,
		UID:  externalID,
		Source: model.SourceInfo{
			System:     newRelicSystem,
			Instance:   model.StableID("newrelic-account", strconv.Itoa(c.accountID)),
			ExternalID: externalID,
		},
		Metadata:  metadata,
		Labels:    map[string]string{},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    status,
	}
}

func newRelicThresholdPriorityCountInvalid(termCount, criticalCount, warningCount int) bool {
	return termCount < 1 ||
		termCount > 2 ||
		criticalCount < 0 ||
		criticalCount > 1 ||
		warningCount < 0 ||
		warningCount > 1 ||
		criticalCount+warningCount != termCount
}

func newRelicInvalidBaselineThresholdDurationCount(condition newRelicCondition) int {
	if !strings.EqualFold(strings.TrimSpace(condition.Type), "BASELINE") {
		return 0
	}
	invalid := 0
	for _, term := range condition.Terms {
		if term.ThresholdDuration < 120 ||
			term.ThresholdDuration > 60*60 ||
			term.ThresholdDuration%60 != 0 {
			invalid++
		}
	}
	return invalid
}

func newRelicBaselineDirectionValidity(condition newRelicCondition) (bool, bool) {
	if !strings.EqualFold(strings.TrimSpace(condition.Type), "BASELINE") {
		return false, false
	}
	switch strings.ToUpper(strings.TrimSpace(condition.BaselineDirection)) {
	case "UPPER_ONLY", "LOWER_ONLY", "UPPER_AND_LOWER":
		return true, false
	default:
		return true, true
	}
}

func newRelicStaticValueFunctionValidity(condition newRelicCondition) (bool, bool) {
	if !strings.EqualFold(strings.TrimSpace(condition.Type), "STATIC") {
		return false, false
	}
	switch strings.ToUpper(strings.TrimSpace(condition.ValueFunction)) {
	case "SINGLE_VALUE", "SUM":
		return true, false
	default:
		return true, true
	}
}

func newRelicQueryScope(query string) (bool, bool) {
	evaluable, scopeClausePresent, err := queryparse.NRQLTopLevelScope(query)
	if err != nil {
		return false, false
	}
	return evaluable, scopeClausePresent
}

func newRelicQueryAlertCompatibility(query string) (bool, int) {
	evaluable, incompatibleClauseCount, err := queryparse.NRQLAlertCompatibility(query)
	if err != nil {
		return false, 0
	}
	return evaluable, incompatibleClauseCount
}

func newRelicSlidingWindowValidity(condition newRelicCondition) (bool, bool, bool, int) {
	if condition.Signal.SlideBy == nil {
		return false, false, false, 0
	}
	windowSeconds := condition.Signal.AggregationWindow
	if windowSeconds < 30 || windowSeconds > 6*60*60 {
		return true, false, false, 0
	}
	slideBySeconds := *condition.Signal.SlideBy
	invalid := slideBySeconds <= 0 ||
		slideBySeconds >= windowSeconds ||
		windowSeconds%slideBySeconds != 0
	if invalid {
		return true, true, true, 0
	}
	return true, true, false, windowSeconds / slideBySeconds
}

func newRelicEventTimerWindowOrder(condition newRelicCondition) (bool, bool) {
	if !strings.EqualFold(strings.TrimSpace(condition.Signal.AggregationMethod), "EVENT_TIMER") ||
		condition.Signal.AggregationTimer < 5 ||
		condition.Signal.AggregationTimer > 20*60 ||
		condition.Signal.AggregationWindow < 30 ||
		condition.Signal.AggregationWindow > 6*60*60 {
		return false, false
	}
	return true, condition.Signal.AggregationTimer < condition.Signal.AggregationWindow
}

func newRelicAggregationDelayValidity(condition newRelicCondition) (bool, bool) {
	delay := condition.Signal.AggregationDelay
	switch strings.ToUpper(strings.TrimSpace(condition.Signal.AggregationMethod)) {
	case "EVENT_FLOW":
		return true, delay < 0 || delay > 20*60
	case "CADENCE":
		return true, delay < 0 || delay > 60*60
	default:
		return false, false
	}
}

func newRelicLossOfSignalConfigured(condition newRelicCondition) bool {
	return condition.Expiration != nil &&
		condition.Expiration.ExpirationDuration != nil &&
		*condition.Expiration.ExpirationDuration > 0 &&
		condition.Expiration.OpenViolationOnExpiration != nil &&
		*condition.Expiration.OpenViolationOnExpiration
}

func newRelicLossOfSignalDurationInvalid(condition newRelicCondition) bool {
	if condition.Expiration == nil || condition.Expiration.ExpirationDuration == nil {
		return false
	}
	duration := *condition.Expiration.ExpirationDuration
	return duration > 0 && (duration < 30 || duration > 48*60*60)
}

func newRelicLossOfSignalDurationShort(condition newRelicCondition) bool {
	if condition.Expiration == nil || condition.Expiration.ExpirationDuration == nil {
		return false
	}
	duration := *condition.Expiration.ExpirationDuration
	return duration >= 30 && duration < 3*60
}

func newRelicLossOfSignalCloseAction(condition newRelicCondition) (bool, bool) {
	if condition.Expiration == nil || condition.Expiration.CloseViolationsOnExpiration == nil {
		return false, false
	}
	return true, *condition.Expiration.CloseViolationsOnExpiration
}

func newRelicEvaluationDelay(condition newRelicCondition) (bool, int, bool) {
	if condition.Signal.EvaluationDelay == nil {
		return false, 0, false
	}
	seconds := *condition.Signal.EvaluationDelay
	return true, seconds, seconds < 0 || seconds > 2*60*60
}

func newRelicThresholdOperatorValid(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ABOVE", "ABOVE_OR_EQUALS", "BELOW", "BELOW_OR_EQUALS", "EQUALS", "NOT_EQUALS":
		return true
	default:
		return false
	}
}

func newRelicThresholdOccurrenceValid(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ALL", "AT_LEAST_ONCE":
		return true
	default:
		return false
	}
}

func newRelicThresholdValueInvalid(value *float64) bool {
	return value == nil || *value < 0 || math.IsNaN(*value) || math.IsInf(*value, 0)
}

func newRelicGapFillOptionValidity(condition newRelicCondition) (string, bool, bool) {
	option := strings.ToUpper(strings.TrimSpace(condition.Signal.FillOption))
	switch option {
	case "NONE", "LAST_VALUE", "STATIC":
		return option, true, false
	default:
		return "", true, true
	}
}

func newRelicStaticGapFillValueValidity(condition newRelicCondition) (bool, bool) {
	if !strings.EqualFold(strings.TrimSpace(condition.Signal.FillOption), "STATIC") {
		return false, false
	}
	if condition.Signal.FillValue == nil ||
		math.IsNaN(*condition.Signal.FillValue) ||
		math.IsInf(*condition.Signal.FillValue, 0) {
		return true, true
	}
	return true, false
}

func newRelicStaticGapFillCriticalBreaches(condition newRelicCondition) (bool, int) {
	if !strings.EqualFold(strings.TrimSpace(condition.Signal.FillOption), "STATIC") ||
		condition.Signal.FillValue == nil ||
		math.IsNaN(*condition.Signal.FillValue) ||
		math.IsInf(*condition.Signal.FillValue, 0) {
		return false, 0
	}
	criticalCount := 0
	breachCount := 0
	for _, term := range condition.Terms {
		if !strings.EqualFold(strings.TrimSpace(term.Priority), "CRITICAL") {
			continue
		}
		criticalCount++
		if term.Threshold == nil || *term.Threshold < 0 ||
			math.IsNaN(*term.Threshold) || math.IsInf(*term.Threshold, 0) {
			return false, 0
		}
		breached, known := newRelicThresholdBreached(
			*condition.Signal.FillValue,
			*term.Threshold,
			term.Operator,
		)
		if !known {
			return false, 0
		}
		if breached {
			breachCount++
		}
	}
	if criticalCount == 0 {
		return false, 0
	}
	return true, breachCount
}

func newRelicThresholdBreached(value, threshold float64, operator string) (bool, bool) {
	switch strings.ToUpper(strings.TrimSpace(operator)) {
	case "ABOVE":
		return value > threshold, true
	case "ABOVE_OR_EQUALS":
		return value >= threshold, true
	case "BELOW":
		return value < threshold, true
	case "BELOW_OR_EQUALS":
		return value <= threshold, true
	case "EQUALS":
		return value == threshold, true
	case "NOT_EQUALS":
		return value != threshold, true
	default:
		return false, false
	}
}

func newRelicGovernanceTags(tags []newRelicTag) map[string]string {
	allowed := map[string]string{
		"service":     model.MetadataService,
		"team":        "team",
		"owner":       model.MetadataOwner,
		"env":         "environment",
		"environment": "environment",
		"lifecycle":   "lifecycle",
		"tier":        "tier",
	}
	result := map[string]string{}
	for _, tag := range tags {
		target, ok := allowed[strings.ToLower(strings.TrimSpace(tag.Key))]
		if !ok || result[target] != "" {
			continue
		}
		for _, value := range tag.Values {
			if value = strings.TrimSpace(value); value != "" {
				result[target] = value
				break
			}
		}
	}
	return result
}

func newRelicOptionalDiagnostic(id, name string, count int, truncated bool, err error) model.Diagnostic {
	diagnostic := model.Diagnostic{
		ID:            id,
		Name:          name,
		Status:        model.ExecutionStatusSucceeded,
		Message:       fmt.Sprintf("%s completed for %d resources", name, count),
		ResourceCount: count,
		Metadata: map[string]string{
			"system":    newRelicSystem,
			"optional":  "true",
			"available": "true",
			"truncated": strconv.FormatBool(truncated),
		},
	}
	if err != nil {
		diagnostic.Status = model.ExecutionStatusWarning
		diagnostic.Message = name + " is unavailable; entity discovery continued"
		diagnostic.Metadata["available"] = "false"
	} else if truncated {
		diagnostic.Status = model.ExecutionStatusWarning
		diagnostic.Message = name + " reached its resource safety limit"
	}
	return diagnostic
}
