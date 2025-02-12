package context

import (
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"net"
	"regexp"
	"strings"
)

var (
	UUID         = regexp.MustCompile(`(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$`)
	OBJECT_ID    = regexp.MustCompile(`^[0-9a-f]{24}$`)
	ULID         = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	NUMBER       = regexp.MustCompile(`^\d+$`)
	DATE         = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}$`)
	EMAIL        = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	HASH         = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$`)
	HASH_LENGTHS = []int{32, 40, 64, 128}
)

func BuildRouteFromURI(path string) string {

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = replaceURLSegmentWithParam(segment)
	}

	route := strings.Join(segments, "/")

	if route == "/" {
		return "/"
	}

	if strings.HasSuffix(route, "/") {
		return route[:len(route)-1]
	}

	return route
}

func replaceURLSegmentWithParam(segment string) string {
	if isStartsWithNumber(segment) && NUMBER.MatchString(segment) {
		return ":number"
	}

	if len(segment) == 36 && UUID.MatchString(segment) {
		return ":uuid"
	}

	if len(segment) == 26 && ULID.MatchString(segment) {
		return ":ulid"
	}

	if len(segment) == 24 && OBJECT_ID.MatchString(segment) {
		return ":objectId"
	}

	if isStartsWithNumber(segment) && DATE.MatchString(segment) {
		return ":date"
	}

	if strings.Contains(segment, "@") && EMAIL.MatchString(segment) {
		return ":email"
	}

	if (strings.Contains(segment, ":") || strings.Contains(segment, ".")) && isIP(segment) {
		return ":ip"
	}

	if containsHashLength(segment) && HASH.MatchString(segment) {
		return ":hash"
	}

	if helpers.LooksLikeASecret(segment) {
		return ":secret"
	}

	return segment
}

func isStartsWithNumber(segment string) bool {
	return len(segment) > 0 && segment[0] >= '0' && segment[0] <= '9'
}

func isIP(segment string) bool {
	return net.ParseIP(segment) != nil
}

func containsHashLength(segment string) bool {
	length := len(segment)
	for _, l := range HASH_LENGTHS {
		if length == l {
			return true
		}
	}
	return false
}
