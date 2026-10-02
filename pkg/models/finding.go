package models

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "CONFIRMED"
	ConfidenceCandidate Confidence = "CANDIDATE"
	ConfidenceObserved  Confidence = "OBSERVED"
)

type Finding struct {
	ID             string     `json:"id"`
	Title          string     `json:"title"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence,omitempty"`
	Category       string     `json:"category"`
	AffectedEntity string     `json:"affected_entity"`
	Description    string     `json:"description"`
	Evidence       []string   `json:"evidence,omitempty"`
	Remediation    string     `json:"remediation"`
	References     []string   `json:"references"`
}
