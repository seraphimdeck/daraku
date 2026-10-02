package detectors

import (
	"fmt"
	"net/http"
	"strings"

	httpClient "github.com/seraphimdeck/daraku/pkg/http"
  "github.com/seraphimdeck/daraku/pkg/models"
)

func (e *Engine) DetectESC11() []models.Finding {
	var findings []models.Finding

	probe := httpClient.NewProbeClient()

	for _, ca := range e.CAs {
		if strings.TrimSpace(ca.DNSHostName) == "" {
			continue
		}

		targetURL := fmt.Sprintf("http://%s/certsrv/mscep/mscep.dll", ca.DNSHostName)

		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "daraku/1.2.0")

		resp, err := probe.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden {

			authHeaders := resp.Header.Values("WWW-Authenticate")
			epaEnabled := false
			for _, h := range authHeaders {
				if strings.Contains(strings.ToLower(h), "tokenbinding") ||
					strings.Contains(strings.ToLower(h), "channelbindings") {
					epaEnabled = true
					break
				}
			}

			if !epaEnabled {
				findings = append(findings, models.Finding{
					ID:             "ESC11",
					Title:          "AD CS ICPR over HTTP without Extended Protection (ESC11)",
					Severity:       models.SeverityHigh,
					Confidence:     models.ConfidenceCandidate,
					Category:       "AD CS",
					AffectedEntity: ca.DNSHostName,
					Description:    fmt.Sprintf("Enterprise CA '%s' mengekspos endpoint MSCEP/ICPR via HTTP pada %s tanpa Extended Protection for Authentication.", ca.Name, targetURL),
					Evidence: []string{
						fmt.Sprintf("HTTP status=%d", resp.StatusCode),
						fmt.Sprintf("WWW-Authenticate=%v", authHeaders),
						fmt.Sprintf("EPA Enabled=%v", epaEnabled),
					},
					Remediation: "Nonaktifkan akses HTTP ke endpoint MSCEP. Gunakan HTTPS dan aktifkan Extended Protection for Authentication (EPA).",
					References:  []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
				})
			}
		}
	}

	return findings
}