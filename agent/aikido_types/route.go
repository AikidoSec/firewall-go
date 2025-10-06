package aikido_types

import "github.com/AikidoSec/firewall-go/agent/ipc/protos"

type RouteData struct {
	Method  string
	Path    string
	APISpec protos.APISpec
}

// BodyDataType represents the type of the body data.
type BodyDataType string

const (
	JSON           BodyDataType = "json"
	FormURLEncoded BodyDataType = "form-urlencoded"
	FormData       BodyDataType = "form-data"
	XML            BodyDataType = "xml"
	Undefined      BodyDataType = ""
)
