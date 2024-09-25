package pkg

import (
	"encoding/json"
	"fmt"
	"time" // Ensure this is imported
)

// Ensure the struct types are correctly defined in your other file
// and imported appropriately in this file.

// Convert to Wazuh string for various event types
func (d *JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	// Ensure that JumpCloudEventType is part of the struct definition
	b, _ := json.Marshal(d)
	return string(b)
}

// Additional methods for other event types
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

// Ensure to define the conversion for other events appropriately
func (e JumpCloudLDAPEvent) convertToWazuhString() string {
	return fmt.Sprintf("LDAP Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}

func (e JumpCloudSystemEvent) convertToWazuhString() string {
	return fmt.Sprintf("System Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.Message, e.Success)
}

func (e JumpCloudRadiusEvent) convertToWazuhString() string {
	return fmt.Sprintf("Radius Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}

func (e JumpCloudDirectoryEvent) convertToWazuhString() string {
	return fmt.Sprintf("Directory Event at %s: %s, Success: %t", e.Timestamp.Format(time.RFC3339), e.ErrorMessage, e.Success)
}
