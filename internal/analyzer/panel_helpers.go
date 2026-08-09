package analyzer

import "monicheck/internal/model"

func isActiveGrafanaPanel(panel model.Resource) bool {
	return panel.Source.System == "grafana" && panel.Status == model.ResourceStatusActive
}
