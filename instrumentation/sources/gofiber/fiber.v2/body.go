package fiber

import (
	"bytes"
	"net/url"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/gofiber/fiber/v2"
)

func extractBody(c *fiber.Ctx) any {
	raw := c.Body()
	if len(raw) == 0 {
		return nil
	}

	jsonResult := zenhttp.ExtractJSONFromReader(bytes.NewReader(raw))
	formResult := extractForm(c)

	if jsonResult != nil && len(formResult) > 0 {
		return []any{jsonResult, formResult}
	}
	if jsonResult != nil {
		return jsonResult
	}
	if len(formResult) > 0 {
		return formResult
	}
	return nil
}

// fasthttp parses multipart bodies at the wire level before middleware
// runs, and rejects mismatched boundaries outright, so the JSON-prefix
// and mislabeled-Content-Type bypasses tested in instrumentation/http
// don't apply to this source.
func extractForm(c *fiber.Ctx) url.Values {
	var result url.Values

	if form, err := c.MultipartForm(); err == nil && form != nil && len(form.Value) > 0 {
		result = url.Values(form.Value)
	}

	if args := c.Context().PostArgs(); args.Len() > 0 {
		if result == nil {
			result = make(url.Values, args.Len())
		}
		for k, v := range args.All() {
			key := string(k)
			result[key] = append(result[key], string(v))
		}
	}

	return result
}
