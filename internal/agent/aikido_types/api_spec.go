package aikido_types

type APIAuthType struct {
	Type         string `json:"type,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	In           string `json:"in,omitempty"`
	Name         string `json:"name,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
}

type DataSchema struct {
	Type       []string               `json:"type"`
	Properties map[string]*DataSchema `json:"properties"`
	Items      *DataSchema            `json:"items"`
	Optional   bool                   `json:"optional"`
}

type APIBodyInfo struct {
	Type   string      `json:"type,omitempty"`
	Schema *DataSchema `json:"schema,omitempty"`
}

type APISpec struct {
	Body  *APIBodyInfo   `json:"body,omitempty"`
	Query *DataSchema    `json:"query,omitempty"`
	Auth  []*APIAuthType `json:"auth,omitempty"`
}
