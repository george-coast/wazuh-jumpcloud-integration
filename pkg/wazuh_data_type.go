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
func (d *JumpCloudPasswordManagerEvent) convertToWazuhString() string {
    d.JumpCloudEventType = "password_manager" // Set the event type
    b, err := json.Marshal(d) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling Password Manager event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (d *JumpCloudSSOEvent) convertToWazuhString() string {
    d.JumpCloudEventType = "sso" // Set the event type
    b, err := json.Marshal(d) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling SSO event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (d *JumpCloudAdminEvent) convertToWazuhString() string {
    d.JumpCloudEventType = "admin" // Set the event type
    b, err := json.Marshal(d) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling Admin event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (e JumpCloudLDAPEvent) convertToWazuhString() string {
    e.JumpCloudEventType = "ldap" // Set the event type
    b, err := json.Marshal(e) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling LDAP event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (e JumpCloudSystemEvent) convertToWazuhString() string {
    e.JumpCloudEventType = "system" // Set the event type
    b, err := json.Marshal(e) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling System event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (e JumpCloudRadiusEvent) convertToWazuhString() string {
    e.JumpCloudEventType = "radius" // Set the event type
    b, err := json.Marshal(e) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling Radius event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}

func (e JumpCloudDirectoryEvent) convertToWazuhString() string {
    e.JumpCloudEventType = "directory" // Set the event type
    b, err := json.Marshal(e) // Convert the struct to JSON
    if err != nil {
        return fmt.Sprintf("Error marshaling Directory event: %s", err) // Handle marshaling error
    }
    return string(b) // Return the JSON string
}
