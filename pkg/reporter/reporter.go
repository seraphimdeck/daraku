package reporter

import "github.com/seraphimdeck/daraku/pkg/models"

type Reporter interface {
	Generate(findings []models.Finding, meta models.AuditMetadata) error
}

type ConsoleReporter struct{}

func (c *ConsoleReporter) Generate(findings []models.Finding, meta models.AuditMetadata) error {
	PrintTerminal(findings)
	return nil
}

type MarkdownReporter struct {
	FilePath string
}

func (m *MarkdownReporter) Generate(findings []models.Finding, meta models.AuditMetadata) error {
	return ExportMarkdown(m.FilePath, findings, meta)
}

type JSONReporter struct {
	FilePath string
}

func (j *JSONReporter) Generate(findings []models.Finding, meta models.AuditMetadata) error {
	return ExportJSON(j.FilePath, findings, meta)
}
