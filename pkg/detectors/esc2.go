package detectors

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func (e *Engine) DetectESC2() []models.Finding {
	var findings []models.Finding

	for _, tmpl := range e.Templates {
		if tmpl.RequiresManagerApproval {
			continue
		}

		hasAnyPurpose := false
		noEKU := len(tmpl.EKUs) == 0

		for _, eku := range tmpl.EKUs {
			if eku == OIDAnyPurpose {
				hasAnyPurpose = true
				break
			}
		}

		if hasAnyPurpose || noEKU {
			findings = append(findings, models.Finding{
				ID:             "ESC2",
				Title:          "AD CS Template with Any Purpose EKU or No EKU (ESC2)",
				Severity:       models.SeverityHigh,
				Confidence:     models.ConfidenceCandidate,
				Category:       "AD CS",
				AffectedEntity: tmpl.Name,
				Description:    fmt.Sprintf("Template '%s' memiliki Any Purpose EKU atau tidak memiliki EKU sama sekali, memungkinkan sertifikat digunakan untuk tujuan apapun termasuk autentikasi.", tmpl.DisplayName),
				Evidence:       []string{fmt.Sprintf("EKUs=%v, NoEKU=%v, AnyPurpose=%v", tmpl.EKUs, noEKU, hasAnyPurpose)},
				Remediation:    "Tentukan EKU yang spesifik sesuai kebutuhan template. Hindari penggunaan Any Purpose EKU.",
				References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
			})
		}
	}

	return findings
}