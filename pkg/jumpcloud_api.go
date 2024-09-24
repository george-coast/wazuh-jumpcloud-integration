package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Valid JumpCloud service types are:
// all: Logs from all services.
// directory: Logs activity in the Admin Portal and User Portal, including admin changes in the directory and admin/user authentications to the Admin Portal and User Portal.
// ldap: Logs user authentications to LDAP, including LDAP Bind and Search event types.
// mdm: Logs MDM command results.
// password_manager: Logs activity related to JumpCloud password manager.
// radius: Logs user authentications to RADIUS, used for Wi-Fi and VPNs.
// software: Logs application activity when software is added, removed, or changed on a macOS, Windows, or Linux device. Events are logged based on changes to an application version during each device check-in.
// sso: Logs user authentications to SAML applications.
// systems: Logs user authentications to MacOS, Windows, and Linux systems, including agent-related events on lockout, password changes, and File Disk Encryption key updates.

// JumpCloudAPI can be used to interact with the JumpCloud API
type JumpCloudAPI struct {
	apiKey  string
	baseURL string
	orgID   string
}

// NewJumpCloudAPIOptions are the options for creating a new JumpCloudAPI object
type NewJumpCloudAPIOptions struct {
	APIKey  string
	BaseURL string
	OrgID   string
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
// NewJumpCloudAPI returns a new JumpCloudAPI object, if you do not provide a base URL, it will default to the JumpCloud API
func NewJumpCloudAPI(options NewJumpCloudAPIOptions) *JumpCloudAPI {
	a := JumpCloudAPI{
		apiKey:  options.APIKey,
		baseURL: options.BaseURL,
		orgID:   options.OrgID,
	}
	if options.BaseURL == "" {
		a.baseURL = "https://api.jumpcloud.com"
	}
	return &a
}

// GetEventsSinceTime returns all JumpCloud events since the given time
func (a *JumpCloudAPI) GetEventsSinceTime(startTime time.Time) (*JumpCloudEvents, error) {
	url := a.baseURL + "/insights/directory/v1/events"
	method := "POST"
	// JumpCloud API requires a time in RFC3339 format
	starterTime := startTime.Format(time.RFC3339)
	payload := strings.NewReader(fmt.Sprintf(`{"service": ["all"], "start_time": "%v", "limit": 10000}`, starterTime))
	// Default Go HTTP client, might need to customize this later
	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Add("x-api-key", a.apiKey)
	req.Header.Add("Content-Type", "application/json")
	if a.orgID != "" {
		req.Header.Add("x-org-id", a.orgID)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v | %v | %v", res.Status, res.StatusCode, err)
	}
	// JumpCloud API returns a 200 even if there are no events
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("error response from JumpCloud: %v | %v | %v", res.Status, res.StatusCode, string(body))
	}
	events, err := decodeJumpCloudEvents(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding JumpCloud response: %v", err)
	}
	return &events, nil
}

type JumpCloudEvents struct {
	LDAP      []JumpCloudLDAPEvent      `json:"ldap_events"`
	Systems   []JumpCloudSystemEvent    `json:"systems"`
	Directory []JumpCloudDirectoryEvent `json:"directory"`
	Radius    []JumpCloudRadiusEvent    `json:"radius"`
	SSO       []JumpCloudSSOEvent       `json:"sso"`
	Admin     []JumpCloudAdminEvent     `json:"admin"`
	PasswordManager   []JumpCloudPasswordManagerEventAPI  `json:"password_manager_events"`
}

type JumpCloudPasswordManagerEventAPI struct {
	InitiatedBy struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Email    string `json:"email"`
		Username string `json:"username"`
	} `json:"initiated_by"`

	GeoIP struct {
		CountryCode   string  `json:"country_code"`
		Timezone      string  `json:"timezone"`
		Latitude      float64 `json:"latitude"`
		ContinentCode string  `json:"continent_code"`
		RegionName    string  `json:"region_name"`
		Longitude     float64 `json:"longitude"`
		RegionCode    string  `json:"region_code"`
	} `json:"geoip"`

	EventType    string `json:"event_type"`
	Resource     struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"resource"`

	Success      bool   `json:"success"`
	Service      string `json:"service"`
	Organization string `json:"organization"`
	UserAgent    struct {
		OSFull   string `json:"os_full"`
		OS       string `json:"os"`
		Name     string `json:"name"`
		OSName   string `json:"os_name"`
		Device   string `json:"device"`
	} `json:"useragent"`

	Version   string `json:"@version"`
	ClientIP  string `json:"client_ip"`
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

type BaseJumpCloudEvent struct {
	Service string `json:"service"`
}

// decodeJumpCloudEvents decodes the raw JumpCloud API response into a JumpCloudEvents object that contains events
// of the varying types
func decodeJumpCloudEvents(raw []byte) (JumpCloudEvents, error) {
	finished := JumpCloudEvents{}
	generic := []map[string]interface{}{}
	err := json.Unmarshal(raw, &generic)
	if err != nil {
		return JumpCloudEvents{}, err
	}
	var events []BaseJumpCloudEvent
	err = json.Unmarshal(raw, &events)
	for i, x := range events {
		fmt.Println(x.Service)
		switch x.Service {
		case "ldap":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling LDAP generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudLDAPEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling LDAP detailed event - will continue: %v\n", err)
				continue
			}
			finished.LDAP = append(finished.LDAP, e)
		case "systems":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Systems generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudSystemEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Systems detailed event - will continue: %v\n", err)
				continue
			}
			finished.Systems = append(finished.Systems, e)
		case "directory":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Directory generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudDirectoryEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Directory detailed event - will continue: %v\n", err)
				continue
			}
			finished.Directory = append(finished.Directory, e)
		case "radius":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Radius generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudRadiusEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Radius detailed event - will continue: %v\n", err)
				continue
			}
			finished.Radius = append(finished.Radius, e)
		case "sso":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling SSO generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudSSOEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling SSO detailed event - will continue: %v\n", err)
				continue
			}
			finished.SSO = append(finished.SSO, e)
		case "admin":
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Admin generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudAdminEvent
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Admin detailed event - will continue: %v\n", err)
				continue
			}
			finished.Admin = append(finished.Admin, e)
		case "password_manager": // New case for password manager events
			b, err := json.Marshal(generic[i])
			if err != nil {
				fmt.Printf("Error marshalling Password Manager generic event - will continue: %v\n", err)
				continue
			}
			var e JumpCloudPasswordManagerEventAPI
			err = json.Unmarshal(b, &e)
			if err != nil {
				fmt.Printf("Error unmarshalling Password Manager detailed event - will continue: %v\n", err)
				continue
			}
			finished.PasswordManager = append(finished.PasswordManager, e)

		}
	}
	return finished, nil
}
