//go:build !go1.27

package cloud

func newSessionID() string {
	return newUUIDv7()
}
