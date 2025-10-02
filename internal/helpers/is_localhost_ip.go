package helpers

// IsLocalhostIP checks if the given IP address is a localhost IP.
func IsLocalhostIP(ip string) bool {
	localhostIPs := []string{"127.0.0.1", "::ffff:127.0.0.1", "::1"}
	for _, localhostIP := range localhostIPs {
		if ip == localhostIP {
			return true
		}
	}
	return false
}
