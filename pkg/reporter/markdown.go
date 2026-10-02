package reporter

import (
	"fmt"
	"os"
	"strings"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func markdownCell(value string) string {
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "\r", "", "\n", "<br>").Replace(value)
}

func ExportMarkdown(filename string, findings []models.Finding, meta models.AuditMetadata) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("gagal membuat file markdown: %w", err)
	}
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("gagal mengatur permission file markdown: %w", err)
	}

	write := func(format string, args ...any) error {
		_, err := fmt.Fprintf(file, format, args...)
		return err
	}

	if err := write("# Active Directory & AD CS Security Audit Report\n\n"); err != nil {
		return err
	}
  if err := write("## Audit Metadata\n\n"); err != nil {
        return err
  }
  if err := write("| Tanggal/Waktu | %s |\n", markdownCell(meta.Timestamp)); err != nil {
        return err
  }
  if err := write("| Hostname | %s |\n", markdownCell(meta.Hostname)); err != nil {
        return err
  }
  if err := write("| Operator | %s |\n", markdownCell(meta.Operator)); err != nil {
        return err
  }
  if err := write("| Target DC | %s |\n", markdownCell(meta.TargetDC)); err != nil {
        return err
  }
  if err := write("| Port | %d |\n\n", meta.Port); err != nil {
        return err
  }
	if err := write("**Total Temuan**: %d\n\n", len(findings)); err != nil {
		return err
	}
	if err := write("| ID | Severity | Confidence | Title | Category | Affected Entity |\n"); err != nil {
		return err
	}
	if err := write("|---|---|---|---|---|---|\n"); err != nil {
		return err
	}

	for _, f := range findings {
		if err := write("| %s | %s | %s | %s | %s | %s |\n",
			markdownCell(f.ID), markdownCell(string(f.Severity)), markdownCell(string(f.Confidence)),
			markdownCell(f.Title), markdownCell(f.Category), markdownCell(f.AffectedEntity)); err != nil {
			return err
		}
	}

	if err := write("\n## Detail Temuan\n\n"); err != nil {
		return err
	}

	for i, f := range findings {
		if err := write("### %d. %s (%s)\n", i+1, markdownCell(f.Title), markdownCell(string(f.Severity))); err != nil {
			return err
		}
		if err := write("- **ID**: `%s`\n", markdownCell(f.ID)); err != nil {
			return err
		}
		if err := write("- **Confidence**: `%s`\n", markdownCell(string(f.Confidence))); err != nil {
			return err
		}
		if err := write("- **Kategori**: %s\n", markdownCell(f.Category)); err != nil {
			return err
		}
		if err := write("- **Entitas Terdampak**: `%s`\n", markdownCell(f.AffectedEntity)); err != nil {
			return err
		}
		if err := write("- **Deskripsi**: %s\n", markdownCell(f.Description)); err != nil {
			return err
		}
		if len(f.Evidence) > 0 {
			if err := write("- **Evidence**:\n"); err != nil {
				return err
			}
			for _, evidence := range f.Evidence {
				if err := write("  - %s\n", markdownCell(evidence)); err != nil {
					return err
				}
			}
		}
    
		if err := write("- **Panduan Remediasi**: %s\n\n", markdownCell(f.Remediation)); err != nil {
			return err
		}
	}

	return nil
}
