package pkg

import (
    "time"
    "fmt"
)

type CustomTime struct {
    time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (ct *CustomTime) UnmarshalJSON(b []byte) error {
    // Strip the quotes around the timestamp
    s := string(b[1 : len(b)-1])

    // Parse the time in the expected format
    t, err := time.Parse(time.RFC3339, s) // Use your specific time format
    if err != nil {
        return err
    }
    ct.Time = t
    return nil
}

// After is a method to compare CustomTime with another time.Time
func (ct CustomTime) After(t time.Time) bool {
    return ct.Time.After(t)
}

// Convert to time.Time
func (ct CustomTime) ToTime() time.Time {
    return ct.Time
}
