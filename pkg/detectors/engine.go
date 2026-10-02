package detectors

import "github.com/seraphimdeck/daraku/pkg/models"

type Engine struct {
	Users     []models.User
	Computers []models.Computer
	Templates []models.CertificateTemplate
	CAs       []models.EnterpriseCA
}

func NewEngine(users []models.User, computers []models.Computer, templates []models.CertificateTemplate, cas []models.EnterpriseCA) *Engine {
	return &Engine{
		Users:     users,
		Computers: computers,
		Templates: templates,
		CAs:       cas,
	}
}

func (e *Engine) RunAll() []models.Finding {
	var findings []models.Finding

	findings = append(findings, e.DetectESC1()...)
	findings = append(findings, e.DetectESC2()...)
	findings = append(findings, e.DetectESC3()...)
	findings = append(findings, e.DetectESC4()...)
	findings = append(findings, e.DetectESC6()...)
	findings = append(findings, e.DetectESC7()...)
	findings = append(findings, e.DetectESC8()...)
	findings = append(findings, e.DetectESC11()...)

	findings = append(findings, e.DetectKerberoast()...)
	findings = append(findings, e.DetectASREP()...)

	findings = append(findings, e.DetectDelegation()...)

	findings = append(findings, e.DetectAdminCount()...)

	findings = append(findings, e.DetectStaleObjects()...)

	return findings
}