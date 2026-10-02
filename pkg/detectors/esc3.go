package detectors

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
)

const (
	OIDCertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1"
)

func (e *Engine) DetectESC3() []models.Finding {
	var findings []models.Finding

	for _, tmpl := range e.Templates {
		if tmpl.RequiresManagerApproval {
			continue
		}

		hasCertAgent := false
		for _, eku := range tmpl.EKUs {
			if eku == OIDCertificateRequestAgent {
				hasCertAgent = true
				break
			}
		}

		if hasCertAgent {
			findings = append(findings, models.Finding{
				ID:             "ESC3",
				Title:          "AD CS Certificate Request Agent Template (ESC3)",
				Severity:       models.SeverityHigh,
				Confidence:     models.ConfidenceCandidate,
				Category:       "AD CS",
				AffectedEntity: tmpl.Name,
				Description:    fmt.Sprintf("Template '%s' memiliki EKU Certificate Request Agent.", tmpl.DisplayName),
				Evidence:       []string{"Certificate Request Agent EKU terdeteksi"},
				Remediation:    "Batasi hak Enrollment Rights pada template ini hanya untuk administrator.",
				References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
			})
		}
	}

	return findings
}