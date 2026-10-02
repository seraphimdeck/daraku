package models

import "time"

type User struct {
	SAMAccountName       string   `json:"sam_account_name"`
	DN                   string   `json:"dn"`
	UserAccountControl   uint32   `json:"user_account_control"`
	ServicePrincipalName []string `json:"service_principal_name"`
	AdminCount           int      `json:"admin_count"`
	DontReqPreauth       bool     `json:"dont_req_preauth"`
	Enabled              bool     `json:"enabled"`
  LastLogon time.Time           `json:"last_logon"`
  TrustedForDelegation bool     `json:"trusted_for_delegation"`
  AllowedToDelegateTo  []string `json:"allowed_to_delegate_to"`
  RBCDConfigured       bool     `json:"rbcd_configured"`
}

type Computer struct {
	SAMAccountName       string   `json:"sam_account_name"`
	DNSHostName          string   `json:"dns_host_name"`
	DN                   string   `json:"dn"`
	UserAccountControl   uint32   `json:"user_account_control"`
	TrustedForDelegation bool     `json:"trusted_for_delegation"`
	AllowedToDelegateTo  []string `json:"allowed_to_delegate_to"`
	AllowedToActOnBehalf []string `json:"allowed_to_act_on_behalf,omitempty"`
	RBCDConfigured       bool     `json:"rbcd_configured"`
	Enabled              bool     `json:"enabled"`
  LastLogon time.Time           `json:"last_logon"`
}

type CertificateTemplate struct {
	Name                    string   `json:"name"`
	DisplayName             string   `json:"display_name"`
	DN                      string   `json:"dn"`
	CertificateNameFlag     uint32   `json:"certificate_name_flag"`
	EnrollmentFlag          uint32   `json:"enrollment_flag"`
	EnrolleeSuppliesSubject bool     `json:"enrollee_supplies_subject"`
	EKUs                    []string `json:"ekus"`
	RequiresManagerApproval bool     `json:"requires_manager_approval"`
	RASignatureCount        int      `json:"ra_signature_count"`
  RawSecurityDescriptor   []byte   `json:"-"`
	SchemaVersion           int      `json:"schema_version"`
}

type EnterpriseCA struct {
	Name        string   `json:"name"`
	DNSHostName string   `json:"dns_host_name"`
	DN          string   `json:"dn"`
	Flags       uint32   `json:"flags"`
	Templates   []string `json:"templates"`
  RawSecurityDescriptor []byte `json:"-"`
	WebEnrollmentURL  string `json:"web_enrollment_url"`
	IsHTTP            bool   `json:"is_http"`
	NTLMAuthSupported bool   `json:"ntlm_auth_supported"`
	EPADisabled       bool   `json:"epa_disabled"`
}
