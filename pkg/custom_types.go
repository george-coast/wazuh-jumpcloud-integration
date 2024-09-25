package pkg

import (
    "encoding/json"
    "time"
)

type CustomTime time.Time

// UnmarshalJSON parses the timestamp from JSON
func (c *CustomTime) UnmarshalJSON(b []byte) error {
    var t string
    if err := json.Unmarshal(b, &t); err != nil {
        return err
    }
    parsedTime, err := time.Parse(time.RFC3339, t)
    if err != nil {
        return err
    }
    *c = CustomTime(parsedTime)
    return nil
}

// MarshalJSON converts the timestamp to JSON
func (c CustomTime) MarshalJSON() ([]byte, error) {
    return json.Marshal(time.Time(c).Format(time.RFC3339))
}
