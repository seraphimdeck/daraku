package ldap

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func (c *Client) SearchPaged(baseDN, filter string, attributes []string, pageSize uint32) ([]*ldap.Entry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	pagingControl := ldap.NewControlPaging(pageSize)
	searchRequest.Controls = []ldap.Control{pagingControl}

	var entries []*ldap.Entry

	for {
		response, err := c.Conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("error saat paged search: %w", err)
		}

		entries = append(entries, response.Entries...)

		updatedControl := ldap.FindControl(response.Controls, ldap.ControlTypePaging)
		if updatedControl == nil {
			break
		}

		cookie := updatedControl.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break
		}

		pagingControl.SetCookie(cookie)
	}

	return entries, nil
}
