package detectors

import (
	"fmt"

	"github.com/seraphimdeck/daraku/pkg/models"
	"github.com/seraphimdeck/daraku/pkg/parser"
)

func (e *Engine) DetectESC4() []models.Finding {
	var findings []models.Finding

	for _, tmpl := range e.Templates {
		if len(tmpl.RawSecurityDescriptor) == 0 {
			continue
		}

		sd, err := parser.ParseSecurityDescriptor(tmpl.RawSecurityDescriptor)
		if err != nil {
			continue
		}

		vulnerableACEs := sd.GetESC4ACEs()
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
			ID:             "ESC4",
			Title:          "AD CS Certificate Template with Dangerous Write Permissions (ESC4)",
			Severity:       models.SeverityCritical,
			Confidence:     models.ConfidenceConfirmed,
			Category:       "AD CS",
			AffectedEntity: tmpl.Name,
			Description: fmt.Sprintf(
				"Template '%s' memiliki hak tulis pada non-admin principal. "+
					"Dapat memodifikasi konfigurasi template untuk mengeksploitasi ESC1 atau ESC2.",
				tmpl.DisplayName,
			),
			Evidence:    evidence,
			Remediation: "Tinjau dan hapus hak WriteDacl, WriteOwner, GenericWrite, atau GenericAll dari akun non-admin pada template ini.",
			References:  []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
		})
	}

	return findings
}