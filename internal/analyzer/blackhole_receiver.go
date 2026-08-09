package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BlackholeReceiverAnalyzerID = "builtin.blackhole_receiver"

var defaultBlackholeReceiverNames = []string{
	"null",
	"blackhole",
	"noop",
	"no-op",
	"none",
	"devnull",
	"/dev/null",
	"discard",
	"drop",
}

type BlackholeReceiverAnalyzer struct{}

func NewBlackholeReceiverAnalyzer() *BlackholeReceiverAnalyzer {
	return &BlackholeReceiverAnalyzer{}
}

func (a *BlackholeReceiverAnalyzer) ID() string {
	return BlackholeReceiverAnalyzerID
}

func (a *BlackholeReceiverAnalyzer) Name() string {
	return "Blackhole Receiver"
}

func (a *BlackholeReceiverAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BlackholeReceiverAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeAlert, model.ResourceTypeReceiver}
}

func (a *BlackholeReceiverAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	alerts, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeAlert})
	if err != nil {
		return nil, err
	}
	receivers, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeReceiver})
	if err != nil {
		return nil, err
	}

	blackholeReceivers := receiverNameSet(stringSliceConfig(analysis.Config, "blackhole_receiver_names", defaultBlackholeReceiverNames))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, alert := range alerts {
		if alert.Source.System != "alertmanager" {
			continue
		}
		if alert.Status != model.ResourceStatusActive {
			continue
		}
		if !isActiveAlertState(alert.Metadata[model.MetadataAlertState]) {
			continue
		}
		matched := blackholeReceiverMatches(alert.Metadata[model.MetadataReceiverNames], blackholeReceivers)
		if len(matched) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), alert.ID),
			Type:     "BlackholeReceiver",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   alert.ID,
				Type: alert.Type,
				Name: alert.Name,
			},
			Evidence: []string{
				fmt.Sprintf("alertmanager alert %q is routed to blackhole receiver(s): %s", alert.Name, strings.Join(matched, ",")),
			},
			Recommendation: "检查 Alertmanager route 和 receiver 配置，避免 firing 告警被路由到空接收器、丢弃接收器或临时测试接收器。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"receivers":   strings.Join(matched, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	for _, receiver := range receivers {
		if !isActiveNotificationReceiver(receiver) {
			continue
		}
		receiverName := strings.TrimSpace(receiver.Metadata["receiver_name"])
		if receiverName == "" {
			receiverName = receiver.Name
		}
		if !blackholeReceivers[strings.ToLower(receiverName)] {
			continue
		}
		if receiver.Metadata["referenced_by_route"] != "true" && receiver.Metadata["seen_in_alerts"] != "true" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), receiver.ID),
			Type:     "BlackholeReceiver",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   receiver.ID,
				Type: receiver.Type,
				Name: receiver.Name,
			},
			Evidence: []string{
				fmt.Sprintf("%s receiver %q is configured as a blackhole receiver", receiver.Source.System, receiver.Name),
			},
			Recommendation: "检查通知路由和 receiver 配置，避免告警被路由到空接收器、丢弃接收器或临时测试接收器。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"receivers":   receiverName,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func receiverNameSet(names []string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		result[name] = true
	}
	return result
}

func blackholeReceiverMatches(raw string, blackholeReceivers map[string]bool) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	matches := make([]string, 0)
	for _, receiver := range strings.Split(raw, ",") {
		receiver = strings.TrimSpace(receiver)
		if receiver == "" {
			continue
		}
		if blackholeReceivers[strings.ToLower(receiver)] {
			matches = append(matches, receiver)
		}
	}
	return matches
}
