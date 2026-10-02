package ldap

import (
	"github.com/seraphimdeck/daraku/pkg/models"
	"strconv"
	"time"
)

func (c *Client) HarvestDomain() ([]models.User, []models.Computer, error) {
	users, err := c.harvestUsers()
	if err != nil {
		return nil, nil, err
	}

	computers, err := c.harvestComputers()
	if err != nil {
		return nil, nil, err
	}

	return users, computers, nil
}

func (c *Client) harvestUsers() ([]models.User, error) {
	attrs := []string{
		"sAMAccountName", "distinguishedName", "userAccountControl",
		"servicePrincipalName", "adminCount",
		"msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"lastLogonTimestamp",
	}

	filter := "(&(objectCategory=person)(objectClass=user))"
	entries, err := c.SearchPaged(c.BaseDN, filter, attrs, 500)
	if err != nil {
		return nil, err
	}

	var users []models.User
	for _, entry := range entries {
		uac, _ := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		adminCount, _ := strconv.Atoi(entry.GetAttributeValue("adminCount"))
		rbcdRaw := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		lastLogon := parseWindowsTime(entry.GetAttributeValue("lastLogonTimestamp"))
		enabled := (uac & 2) == 0
		dontReqPreauth := (uac & 0x00400000) != 0

		user := models.User{
			SAMAccountName:       entry.GetAttributeValue("sAMAccountName"),
			DN:                   entry.DN,
			UserAccountControl:   uint32(uac),
			ServicePrincipalName: entry.GetAttributeValues("servicePrincipalName"),
			AdminCount:           adminCount,
			DontReqPreauth:       dontReqPreauth,
			Enabled:              enabled,
			TrustedForDelegation: (uac & 0x00080000) != 0,
			AllowedToDelegateTo:  entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
			RBCDConfigured:       len(rbcdRaw) > 0,
			LastLogon:            lastLogon,
		}

		users = append(users, user)
	}

	return users, nil
}

func (c *Client) harvestComputers() ([]models.Computer, error) {
	attrs := []string{
		"sAMAccountName", "dNSHostName", "distinguishedName",
		"userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"lastLogonTimestamp",
	}

	filter := "(objectClass=computer)"
	entries, err := c.SearchPaged(c.BaseDN, filter, attrs, 500)
	if err != nil {
		return nil, err
	}

	var computers []models.Computer
	for _, entry := range entries {
		uac, _ := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		enabled := (uac & 2) == 0
		unconstrained := (uac & 0x00080000) != 0
		rbcdRaw := entry.GetRawAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")
		lastLogon := parseWindowsTime(entry.GetAttributeValue("lastLogonTimestamp"))

		comp := models.Computer{
			SAMAccountName:       entry.GetAttributeValue("sAMAccountName"),
			DNSHostName:          entry.GetAttributeValue("dNSHostName"),
			DN:                   entry.DN,
			UserAccountControl:   uint32(uac),
			TrustedForDelegation: unconstrained,
			AllowedToDelegateTo:  entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
			RBCDConfigured:       len(rbcdRaw) > 0,
			Enabled:              enabled,
			LastLogon:            lastLogon,
		}
		computers = append(computers, comp)
	}

	return computers, nil
}

func parseWindowsTime(s string) time.Time {
	if s == "" || s == "0" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	unixNano := (n - epochDiff) * 100
	return time.Unix(0, unixNano)
}