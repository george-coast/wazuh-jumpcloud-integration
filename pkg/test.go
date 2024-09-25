package pkg

import (
    "fmt"
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

// JumpCloudPasswordManagerEvent represents an event with a timestamp
type JumpCloudPasswordManagerEvent struct {
    Timestamp CustomTime // Your struct may have additional fields
    // Other fields...
}

// handleLogs processes an array of JumpCloudPasswordManagerEvent
func handleLogs(events []JumpCloudPasswordManagerEvent) {
    someTime := time.Now().Add(-48 * time.Hour) // Define reference time

    for _, x := range events {
        if x.Timestamp.ToTime().After(someTime) {
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
