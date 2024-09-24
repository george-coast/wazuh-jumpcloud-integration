package pkg

// Simple version to text JSON strings for Wazuh to ingest, might need to customize these later

import "encoding/json"

func (d *JumpCloudSystemEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "system"
	b, _ := json.Marshal(d)
	return string(b)
}



func (d *JumpCloudDirectoryEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "directory"
	b, _ := json.Marshal(d)
	return string(b)
}

func (d *JumpCloudRadiusEvent) convertToWazuhString() string {
	d.JumpCloudEventType = "radius"
	b, _ := json.Marshal(d)
	return string(b)
}

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
	return fmt.Sprintf("LDAP Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}

// Similarly, add for other event types...

type JumpCloudSystemEvent struct {
	// Fields as before...
}

func (e JumpCloudSystemEvent) convertToWazuhString() string {
	return fmt.Sprintf("System Event at %s: %s, Success: %t", e.Timestamp, e.Message, e.Success)
}

type JumpCloudDirectoryEvent struct {
	// Fields as before...
}

func (e JumpCloudDirectoryEvent) convertToWazuhString() string {
	return fmt.Sprintf("Directory Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}

type JumpCloudRadiusEvent struct {
	// Fields as before...
}

func (e JumpCloudRadiusEvent) convertToWazuhString() string {
	return fmt.Sprintf("Radius Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}

type JumpCloudSSOEvent struct {
	// Fields as before...
}

func (e JumpCloudSSOEvent) convertToWazuhString() string {
	return fmt.Sprintf("SSO Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}

type JumpCloudAdminEvent struct {
	// Fields as before...
}

func (e JumpCloudAdminEvent) convertToWazuhString() string {
	return fmt.Sprintf("Admin Event at %s: %s", e.Timestamp, e.JumpCloudEventType)
}

type JumpCloudPasswordManagerEvent struct {
	// Fields as before...
}

func (e JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	return fmt.Sprintf("Password Manager Event at %s: %s, Success: %t", e.Timestamp, e.Operation, e.Success)
}
