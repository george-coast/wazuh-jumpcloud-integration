package pkg

import (
    "fmt"
    "encoding/json"
    "time"
)

// CustomTime is a custom type for handling time
type CustomTime struct {
    time.Time
}

// ToTime converts CustomTime to time.Time
func (c *CustomTime) ToTime() time.Time {
    return c.Time
}
// UnmarshalJSON customizes the JSON unmarshalling for CustomTime.
func (ct *CustomTime) UnmarshalJSON(b []byte) error {
    // Remove the surrounding quotes
    s := string(b)
    if s == "null" {
        return nil // Allow null values
    }
    
    // Parse the time from the JSON string
    parsedTime, err := time.Parse(`"`+time.RFC3339+`"`, s)
    if err != nil {
        return fmt.Errorf("could not parse time: %v", err)
    }
    ct.Time = parsedTime
    return nil
}
// JumpCloudPasswordManagerEvent represents an event with a timestamp


func (ct CustomTime) After(t time.Time) bool {
    return ct.Time.After(t)
}

// handleLogs processes an array of JumpCloudPasswordManagerEvent
func handleLogs(events []JumpCloudPasswordManagerEvent) {
    someTime := time.Now().Add(-48 * time.Hour) // Define reference time

    for _, x := range events {
        if x.Timestamp.ToTime().After(time.Now()) {
            // Logic for handling recent events
            fmt.Println("Recent event found:", x)
            // Add your processing logic here
        } else {
            // Logic for older events
            fmt.Println("Event is older than 48 hours:", x)
        }
    }
}

func main() {
    // Example usage of handleLogs
    events := []JumpCloudPasswordManagerEvent{
        {Timestamp: CustomTime{Time: time.Now().Add(-24 * time.Hour)}}, // Recent event
        {Timestamp: CustomTime{Time: time.Now().Add(-50 * time.Hour)}}, // Older event
    }

    handleLogs(events)
}
