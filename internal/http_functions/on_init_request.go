package http_functions

import "github.com/AikidoSec/firewall-go/internal/context"

func OnInitRequest(ctx context.Context) {
	context.Set(ctx) // Store the new context
}
