package pkg

import (
	"fmt"
	"os"
	"time"
)

type TimeTracker interface {
	UpdateLast(newTime time.Time) error
	GetLastTime() time.Time
}

type JumpCloudConnector interface {
	GetEventsSinceTime(time.Time) (*JumpCloudEvents, error)
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

// RunService is the main entry point for the service. It will run a single time and return an error if one is encountered.
func RunService(timeTracker TimeTracker, j JumpCloudConnector, pathToLogFile string) error {
    f, err := os.OpenFile(pathToLogFile,
        os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    lastTime := timeTracker.GetLastTime()
    e, err := j.GetEventsSinceTime(lastTime)
    if err != nil {
        return err
    }
    // Before doing anything make sure there is at least one event
    if len(e.Directory) == 0 && len(e.LDAP) == 0 && len(e.Systems) == 0 && len(e.SSO) == 0 && len(e.Radius) == 0 && len(e.PasswordManager) == 0 {
        return nil
    }
    lastEventSeen := lastTime

    // Process Directory events
    for _, x := range e.Directory {
        timestamp, err := time.Parse(time.RFC3339, x.Timestamp)
        if err != nil {
            fmt.Printf("Error parsing directory timestamp: %v\n", err)
            continue
        }
        if timestamp.After(lastEventSeen) {
            lastEventSeen = timestamp
        }
        _, writeErr := f.WriteString(x.convertToWazuhString() + "\n")
        if writeErr != nil {
            fmt.Printf("Error writing to file: %s", writeErr.Error())
        }
    }

    // Process LDAP events
    for _, x := range e.LDAP {
        timestamp, err := time.Parse(time.RFC3339, x.Timestamp)
        if err != nil {
            fmt.Printf("Error parsing LDAP timestamp: %v\n", err)
            continue
        }
        if timestamp.After(lastEventSeen) {
            lastEventSeen = timestamp
        }
        _, writeErr := f.WriteString(x.convertToWazuhString() + "\n")
        if writeErr != nil {
            fmt.Printf("Error writing to file: %s", writeErr.Error())
        }
    }

    // Process Systems events
    for _, x := range e.Systems {
        timestamp, err := time.Parse(time.RFC3339, x.Timestamp)
        if err != nil {
            fmt.Printf("Error parsing systems timestamp: %v\n", err)
            continue
        }
        if timestamp.After(lastEventSeen) {
            lastEventSeen = timestamp
        }
        _, writeErr := f.WriteString(x.convertToWazuhString() + "\n")
        if writeErr != nil {
            fmt.Printf("Error writing to file: %s", writeErr.Error())
        }
    }

    // Process SSO events
    for _, x := range e.SSO {
        timestamp, err := time.Parse(time.RFC3339, x.Timestamp)
        if err != nil {
            fmt.Printf("Error parsing SSO timestamp: %v\n", err)
            continue
        }
        if timestamp.After(lastEventSeen) {
            lastEventSeen = timestamp
        }
        _, writeErr := f.WriteString(x.convertToWazuhString() + "\n")
        if writeErr != nil {
            fmt.Printf("Error writing to file: %s", writeErr.Error())
        }
    }

    // Process Password Manager events
    for _, x := range e.PasswordManager {
        timestamp, err := time.Parse(time.RFC3339, x.Timestamp)
        if err != nil {
            fmt.Printf("Error parsing password manager timestamp: %v\n", err)
            continue
        }
        if timestamp.After(lastEventSeen) {
            lastEventSeen = timestamp
        }
        _, writeErr := f.WriteString(x.convertToWazuhString() + "\n")
        if writeErr != nil {
            fmt.Printf("Error writing to file: %s", writeErr.Error())
        }
    }

    err = timeTracker.UpdateLast(lastEventSeen.Add(time.Second * 1))
    return err
}
