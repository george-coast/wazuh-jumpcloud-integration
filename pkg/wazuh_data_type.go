package pkg

import (
	"encoding/json"
	"fmt"
)

// Convert to Wazuh string for various event types
func (d *JumpCloudSSOEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "sso"
	b, _ := json.Marshal(d)
	return string(b)
}

func (d *JumpCloudAdminEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "admin"
	b, _ := json.Marshal(d)
	return string(b)
}

func (d *JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "password_manager"
	b, _ := json.Marshal(d)
	return string(b)
}

func (e JumpCloudLDAPEvent) convertToWazuhString() string {
	return fmt.Sprintf("LDAP Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}

func (e JumpCloudSystemEvent) convertToWazuhString() string {
	return fmt.Sprintf("System Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.Message, e.Success)
}

func (e JumpCloudRadiusEvent) convertToWazuhString() string {
	return fmt.Sprintf("Radius Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}

func (e JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	return fmt.Sprintf("Password Manager Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.Operation, e.Success)
}

// Ensure the function for JumpCloudDirectoryEvent is added
func (e JumpCloudDirectoryEvent) convertToWazuhString() string {
	return fmt.Sprintf("Directory Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}
