package detectors

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
	"github.com/seraphimdeck/daraku/pkg/parser"
)

func (e *Engine) DetectESC7() []models.Finding {
	var findings []models.Finding

	for _, ca := range e.CAs {
		if len(ca.RawSecurityDescriptor) == 0 {
			continue
		}

		sd, err := parser.ParseSecurityDescriptor(ca.RawSecurityDescriptor)
		if err != nil {
			continue
		}

		vulnerableACEs := sd.GetESC7ACEs()
		if len(vulnerableACEs) == 0 {
			continue
		}

		var evidence []string
		for _, ace := range vulnerableACEs {
			if ace.SID != nil {
				evidence = append(evidence, fmt.Sprintf(
					"SID=%s AccessMask=0x%08x",
					ace.SID.String(),
					ace.AccessMask,
				))
			}
		}

		findings = append(findings, models.Finding{
			ID:             "ESC7",
			Title:          "Enterprise CA with Dangerous Manage Rights (ESC7)",
			Severity:       models.SeverityCritical,
			Confidence:     models.ConfidenceConfirmed,
			Category:       "AD CS",
			AffectedEntity: ca.Name,
			Description: fmt.Sprintf(
				"Enterprise CA '%s' memiliki hak Manage CA atau Manage Certificates "+
					"pada non-admin principal. Principal tersebut dapat menyetujui "+
					"certificate request yang pending atau mengubah konfigurasi CA.",
				ca.Name,
			),
			Evidence:    evidence,
			Remediation: "Tinjau dan hapus hak Manage CA dan Manage Certificates dari akun non-admin melalui certsrv.msc.",
			References:  []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
		})
	}

	return findings
}