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

// RunService is the main entry point for the service.
func RunService(timeTracker TimeTracker, j JumpCloudConnector, pathToLogFile string) error {
	f, err := os.OpenFile(pathToLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	lastTime := timeTracker.GetLastTime()
	e, err := j.GetEventsSinceTime(lastTime)
	if err != nil {
		return err
	}

	// Check if there are any events
	if len(e.Directory) == 0 && len(e.LDAP) == 0 && len(e.Systems) == 0 && len(e.SSO) == 0 && len(e.Radius) == 0 && len(e.PasswordManager) == 0 {
		return nil
	}
	lastEventSeen := lastTime

	// Process Directory events
	for _, x := range e.Directory {
		if x.Timestamp.ToTime().After(lastEventSeen) {
			lastEventSeen = x.Timestamp.ToTime()
		}
		if _, writeErr := f.WriteString(x.convertToWazuhString() + "\n"); writeErr != nil {
			fmt.Printf("Error writing to file: %s", writeErr.Error())
		}
	}

	// Process LDAP events
	for _, x := range e.LDAP {
		if x.Timestamp.ToTime().After(lastEventSeen) {
			lastEventSeen = x.Timestamp.ToTime()
		}
		if _, writeErr := f.WriteString(x.convertToWazuhString() + "\n"); writeErr != nil {
			fmt.Printf("Error writing to file: %s", writeErr.Error())
		}
	}

	// Process Systems events
	for _, x := range e.Systems {
		if x.Timestamp.ToTime().After(lastEventSeen) {
			lastEventSeen = x.Timestamp.ToTime()
		}
		if _, writeErr := f.WriteString(x.convertToWazuhString() + "\n"); writeErr != nil {
			fmt.Printf("Error writing to file: %s", writeErr.Error())
		}
	}

	// Process SSO events
	for _, x := range e.SSO {
		if x.Timestamp.ToTime().After(lastEventSeen) {
			lastEventSeen = x.Timestamp.ToTime()
		}
		if _, writeErr := f.WriteString(x.convertToWazuhString() + "\n"); writeErr != nil {
			fmt.Printf("Error writing to file: %s", writeErr.Error())
		}
	}

	// Process Password Manager events
	for _, x := range e.PasswordManager {
		if x.Timestamp.ToTime().After(lastEventSeen) {
			lastEventSeen = x.Timestamp.ToTime()
		}
		if _, writeErr := f.WriteString(x.convertToWazuhString() + "\n"); writeErr != nil {
			fmt.Printf("Error writing to file: %s", writeErr.Error())
		}
	}

	err = timeTracker.UpdateLast(lastEventSeen.Add(time.Second))
	return err
}

