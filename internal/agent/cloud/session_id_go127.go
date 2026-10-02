//go:build go1.27

package cloud

import "uuid"

func newSessionID() string {
	return uuid.NewV7().String()
}
