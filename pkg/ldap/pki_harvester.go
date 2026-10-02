package ldap

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
	"strconv"
)

func (c *Client) HarvestPKI() ([]models.CertificateTemplate, []models.EnterpriseCA, error) {
	templates, err := c.harvestTemplates()
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menemukan Certificate Templates: %w", err)
	}

	cas, err := c.harvestEnterpriseCAs()
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menemukan Enterprise CAs: %w", err)
	}

	return templates, cas, nil
}

func (c *Client) harvestTemplates() ([]models.CertificateTemplate, error) {
	pkiDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", c.ConfigDN)
	attrs := []string{
		"cn", "displayName", "distinguishedName",
		"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
		"pKIExtendedKeyUsage", "msPKI-RA-Signature", "msPKI-Template-Schema-Version", "nTSecurityDescriptor",
	}

	entries, err := c.SearchPaged(pkiDN, "(objectClass=pKICertificateTemplate)", attrs, 500)
	if err != nil {
		return nil, err
	}

	var result []models.CertificateTemplate
	for _, entry := range entries {
		nameFlag, _ := strconv.ParseUint(entry.GetAttributeValue("msPKI-Certificate-Name-Flag"), 10, 32)
		enrollFlag, _ := strconv.ParseUint(entry.GetAttributeValue("msPKI-Enrollment-Flag"), 10, 32)
		schemaVer, _ := strconv.Atoi(entry.GetAttributeValue("msPKI-Template-Schema-Version"))
		raSig, _ := strconv.Atoi(entry.GetAttributeValue("msPKI-RA-Signature"))

		enrolleeSupplies := (nameFlag & 1) != 0
		requiresApproval := (enrollFlag & 2) != 0

		tmpl := models.CertificateTemplate{
			Name:                    entry.GetAttributeValue("cn"),
			DisplayName:             entry.GetAttributeValue("displayName"),
			DN:                      entry.DN,
			CertificateNameFlag:     uint32(nameFlag),
			EnrollmentFlag:          uint32(enrollFlag),
			EnrolleeSuppliesSubject: enrolleeSupplies,
			EKUs:                    entry.GetAttributeValues("pKIExtendedKeyUsage"),
			RequiresManagerApproval: requiresApproval,
			RASignatureCount:        raSig,
			SchemaVersion:           schemaVer,
		}
    tmpl.RawSecurityDescriptor = entry.GetRawAttributeValue("nTSecurityDescriptor")
		result = append(result, tmpl)
	}

	return result, nil
}

func (c *Client) harvestEnterpriseCAs() ([]models.EnterpriseCA, error) {
	caDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", c.ConfigDN)
	attrs := []string{
		"cn", "dNSHostName", "distinguishedName", "flags", "certificateTemplates", "nTSecurityDescriptor",
	}

	entries, err := c.SearchPaged(caDN, "(objectClass=pPKICertificateAuthority)", attrs, 500)
	if err != nil {
		return nil, err
	}

	var result []models.EnterpriseCA
	for _, entry := range entries {
		flags, _ := strconv.ParseUint(entry.GetAttributeValue("flags"), 10, 32)

		ca := models.EnterpriseCA{
			Name:        entry.GetAttributeValue("cn"),
			DNSHostName: entry.GetAttributeValue("dNSHostName"),
			DN:          entry.DN,
			Flags:       uint32(flags),
			Templates:   entry.GetAttributeValues("certificateTemplates"),
		}
    ca.RawSecurityDescriptor = entry.GetRawAttributeValue("nTSecurityDescriptor")
		result = append(result, ca)
	}

	return result, nil
}
