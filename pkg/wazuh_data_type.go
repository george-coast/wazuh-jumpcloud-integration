package pkg

import (
	"encoding/json"
	"fmt"
	"time" // Ensure this is imported
)

// This file contains the definitions and methods for JumpCloud event types.
// Each event type has a method to convert its struct representation into a JSON string
// that can be consumed by Wazuh for logging and monitoring.

// Convert to Wazuh string for various event types
func (e *JumpCloudLDAPEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

func (e *JumpCloudSSOEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

func (d *JumpCloudAdminEvent) convertToWazuhString() string {
	return fmt.Sprintf("Admin Event: %s initiated by %s at %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

func (e *JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

func (e *JumpCloudSystemEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}
func (e *JumpCloudRadiusEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

func (e *JumpCloudDirectoryEvent) convertToWazuhString() string {
	return fmt.Sprintf("%s: %s on %s", e.EventType, e.Operation, e.Timestamp.Format(time.RFC3339))
}

