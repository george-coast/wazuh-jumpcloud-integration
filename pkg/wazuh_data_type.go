package pkg

// Simple version to text JSON strings for Wazuh to ingest, might need to customize these later

import "encoding/json"




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



func (e JumpCloudSystemEvent) convertToWazuhString() string {
	return fmt.Sprintf("System Event at %s: %s, Success: %t", e.Timestamp, e.Message, e.Success)
}





func (e JumpCloudRadiusEvent) convertToWazuhString() string {
	return fmt.Sprintf("Radius Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}



func (e JumpCloudSSOEvent) convertToWazuhString() string {
	return fmt.Sprintf("SSO Event at %s: %s, Success: %t", e.Timestamp, e.ErrorMessage, e.Success)
}



func (e JumpCloudAdminEvent) convertToWazuhString() string {
	return fmt.Sprintf("Admin Event at %s: %s", e.Timestamp, e.JumpCloudEventType)
}



func (e JumpCloudPasswordManagerEvent) convertToWazuhString() string {
	return fmt.Sprintf("Password Manager Event at %s: %s, Success: %t", e.Timestamp, e.Operation, e.Success)
}
