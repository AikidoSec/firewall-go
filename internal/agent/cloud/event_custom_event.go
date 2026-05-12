package cloud

type CustomEvent struct {
	Name      string `json:"name"`
	UserID    string `json:"userId,omitempty"`
	IPAddress string `json:"ipAddress,omitempty"`
	Metadata  any    `json:"metadata,omitempty"`
}

func (c *Client) SendCustomEvent(event CustomEvent) {
	_, err := c.sendCloudRequest(c.realtimeEndpoint, eventsAPIRoute, eventsAPIMethod, event)
	if err != nil {
		logCloudRequestError("Error sending custom event: ", err)
	}
}
