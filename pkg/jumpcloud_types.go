package pkg

import (
    "fmt"
    "time"
)

type JumpCloudLDAPEvent struct {
    JumpCloudEventType string `json:"jumpcloud_event_type"`
    ErrorMessage       string `json:"error_message"`
    InitiatedBy        struct {
        Type     string `json:"type"`
        Username string `json:"username"`
    } `json:"initiated_by"`
    OperationType  string    `json:"operation_type"`
    StartTLS       bool      `json:"start_tls"`
    TLSEstablished bool      `json:"tls_established"`
    Dn             string    `json:"dn"`
    AuthMeta       struct {
        AuthMethods struct {
            Password struct {
                Success bool `json:"success"`
            } `json:"password"`
        } `json:"auth_methods"`
    } `json:"auth_meta,omitempty"`
    Mech            string    `json:"mech,omitempty"`
    AuthMethod      string    `json:"auth_method,omitempty"`
    EventType       string    `json:"event_type"`
    ConnectionID    string    `json:"connection_id"`
    Success         bool      `json:"success"`
    Service         string    `json:"service"`
    Organization    string    `json:"organization"`
    Version         string    `json:"@version"`
    ErrorCode       int       `json:"error_code"`
    ID              string    `json:"id"`
    OperationNumber int       `json:"operation_number"`
    Operation       string    `json:"operation"`
    Timestamp      CustomTime `json:"timestamp"`
    Username        string    `json:"username"`
    Deref           int       `json:"deref,omitempty"`
    Filter          string    `json:"filter,omitempty"`
    Scope           int       `json:"scope,omitempty"`
    NumberOfResults int       `json:"number_of_results,omitempty"`
    Attr            string    `json:"attr,omitempty"`
    Base            string    `json:"base,omitempty"`
}

// Similarly, add for other event types...

type JumpCloudSystemEvent struct {
    JumpCloudEventType string    `json:"jumpcloud_event_type"`
    InitiatedBy        struct {
        Type     string `json:"type"`
        Username string `json:"username"`
    } `json:"initiated_by,omitempty"`
    Geoip struct {
        CountryCode   string  `json:"country_code"`
        Timezone      string  `json:"timezone"`
        Latitude      float64 `json:"latitude"`
        ContinentCode string  `json:"continent_code"`
        RegionName    string  `json:"region_name"`
        RegionCode    string  `json:"region_code"`
        Longitude     float64 `json:"longitude"`
    } `json:"geoip,omitempty"`
    Message          string    `json:"message,omitempty"`
    System           struct {
        Hostname    string `json:"hostname"`
        DisplayName string `json:"displayName"`
        ID          string `json:"id"`
    } `json:"system,omitempty"`
    EventType       string    `json:"event_type"`
    Success         bool      `json:"success"`
    Service         string    `json:"service"`
    Organization    string    `json:"organization"`
    Version         string    `json:"@version"`
    ClientIP        string    `json:"client_ip,omitempty"`
    SystemTimestamp time.Time `json:"system_timestamp,omitempty"`
    ID              string    `json:"id"`
    Operation       string    `json:"operation"`
    Timestamp      CustomTime `json:"timestamp"`
    Username        string    `json:"username,omitempty"`
    ProcessName     string    `json:"process_name,omitempty"`
    WindowsMeta     struct {
        LogonType string `json:"logon_type"`
    } `json:"windows_meta,omitempty"`
    Resource struct {
        Hostname    string `json:"hostname"`
        DisplayName string `json:"displayName"`
        ID          string `json:"id"`
        Type        string `json:"type"`
    } `json:"resource,omitempty"`
    Changes []struct {
        Field string `json:"field"`
    } `json:"changes,omitempty"`
}

type JumpCloudDirectoryEvent struct {
    JumpCloudEventType string `json:"jumpcloud_event_type"`
    InitiatedBy        struct {
        ID       string `json:"id"`
        Type     string `json:"type"`
        Username string `json:"username"`
        Email    string `json:"email"`
    } `json:"initiated_by,omitempty"`
    ErrorMessage string `json:"error_message,omitempty"`
    Geoip        struct {
        CountryCode   string  `json:"country_code"`
        Timezone      string  `json:"timezone"`
        Latitude      float64 `json:"latitude"`
        ContinentCode string  `json:"continent_code"`
        RegionName    string  `json:"region_name"`
        Longitude     float64 `json:"longitude"`
        RegionCode    string  `json:"region_code"`
    } `json:"geoip,omitempty"`
    AuthContext struct {
        AuthMethods struct {
            Password struct {
                Success bool `json:"success"`
            } `json:"password"`
        } `json:"auth_methods"`
    } `json:"auth_context,omitempty"`
    Useragent struct {
        Os        string `json:"os"`
        Minor     string `json:"minor"`
        OsMinor   string `json:"os_minor"`
        OsMajor   string `json:"os_major"`
        OsVersion string `json:"os_version"`
        Version   string `json:"version"`
        OsPatch   string `json:"os_patch"`
        Patch     string `json:"patch"`
        OsFull    string `json:"os_full"`
        Major     string `json:"major"`
        Name      string `json:"name"`
        OsName    string `json:"os_name"`
        Device    string `json:"device"`
    } `json:"useragent,omitempty"`
    Mfa          bool      `json:"mfa,omitempty"`
    EventType    string    `json:"event_type"`
    Provider     string    `json:"provider"`
    Success      bool      `json:"success"`
    Service      string    `json:"service"`
    Organization string    `json:"organization"`
    Version      string    `json:"@version"`
    ClientIP     string    `json:"client_ip,omitempty"`
    ID           string    `json:"id"`
    Operation    string    `json:"operation"`
    Timestamp  CustomTime  `json:"timestamp"`
}

type JumpCloudRadiusEvent struct {
    JumpCloudEventType string `json:"jumpcloud_event_type"`
    InitiatedBy        struct {
        Type     string `json:"type"`
        Username string `json:"username"`
    } `json:"initiated_by"`
    ErrorMessage interface{} `json:"error_message"`
    AuthType     string      `json:"auth_type"`
    Geoip        struct {
        CountryCode   string  `json:"country_code"`
        Timezone      string  `json:"timezone"`
        Latitude      float64 `json:"latitude"`
        ContinentCode string  `json:"continent_code"`
        RegionName    string  `json:"region_name"`
        RegionCode    string  `json:"region_code"`
        Longitude     float64 `json:"longitude"`
    } `json:"geoip,omitempty"`
    NasMfaState string `json:"nas_mfa_state"`
    EapType     string `json:"eap_type"`
    Outer       struct {
        ErrorMessage interface{} `json:"error_message"`
        EapType      interface{} `json:"eap_type"`
        Username     string      `json:"username"`
    } `json:"outer"`
    Mfa      bool `json:"mfa"`
    AuthMeta struct {
        UserPasswordEnabled bool   `json:"user_password_enabled"`
        DeviceCertEnabled   bool   `json:"device_cert_enabled"`
        UserCertEnabled     bool   `json:"user_cert_enabled"`
        AuthIdp             string `json:"auth_idp"`
        UseridType          string `json:"userid_type"`
    } `json:"auth_meta"`
    EventType string `json:"event_type"`
    MfaMeta   struct {
        Type string `json:"type"`
    } `json:"mfa_meta"`
    Success      bool      `json:"success"`
    Service      string    `json:"service"`
    Organization string    `json:"organization"`
    Version      string    `json:"@version"`
    ClientIP     string    `json:"client_ip"`
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    Operation    string    `json:"operation"`
    Timestamp   CustomTime `json:"timestamp"`
}

type JumpCloudSSOEvent struct {
    JumpCloudEventType string `json:"jumpcloud_event_type"`
    InitiatedBy        struct {
        ID       string `json:"id"`
        Type     string `json:"type"`
        Username string `json:"username"`
    } `json:"initiated_by"`
    ErrorMessage string `json:"error_message"`
    Geoip        struct {
        CountryCode   string  `json:"country_code"`
        Timezone      string  `json:"timezone"`
        Latitude      float64 `json:"latitude"`
        ContinentCode string  `json:"continent_code"`
        RegionName    string  `json:"region_name"`
        Longitude     float64 `json:"longitude"`
        RegionCode    string  `json:"region_code"`
    } `json:"geoip,omitempty"`
    SsoTokenSuccess bool `json:"sso_token_success"`
    AuthContext     struct {
        AuthMethods struct {
        } `json:"auth_methods"`
        PoliciesApplied []struct {
            Metadata struct {
                ResourceType string `json:"resource_type"`
            } `json:"metadata"`
        } `json:"policies_applied,omitempty"`
    } `json:"auth_context,omitempty"`
    EventType    string    `json:"event_type"`
    Success      bool      `json:"success"`
    Service      string    `json:"service"`
    Organization string    `json:"organization"`
    Version      string    `json:"@version"`
    ClientIP     string    `json:"client_ip"`
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    Operation    string    `json:"operation"`
    Timestamp   CustomTime `json:"timestamp"`
}

type JumpCloudPasswordManagerEvent struct {
    JumpCloudEventType string    `json:"jumpcloud_event_type"`
    InitiatedBy        struct {
        ID       string `json:"id"`
        Type     string `json:"type"`
        Username string `json:"username"`
    } `json:"initiated_by"`
    ErrorMessage string `json:"error_message"`
    Account      struct {
        ID       string `json:"id"`
        Username string `json:"username"`
        Service  string `json:"service"`
    } `json:"account"`
    EventType    string    `json:"event_type"`
    Success      bool      `json:"success"`
    Service      string    `json:"service"`
    Organization string    `json:"organization"`
    Version      string    `json:"@version"`
    ClientIP     string    `json:"client_ip"`
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    Operation    string    `json:"operation"`
    Timestamp   CustomTime `json:"timestamp"`
    Operation    string    `json:"operation"`
}
