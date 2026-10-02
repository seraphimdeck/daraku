package models

type AuditMetadata struct {
    Timestamp  string `json:"timestamp"`
    Hostname   string `json:"hostname"`
    Operator   string `json:"operator"`
    TargetDC   string `json:"target_dc"`
    Port       int    `json:"port"`
}