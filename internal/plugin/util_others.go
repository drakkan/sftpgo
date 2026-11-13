//go:build !windows

package plugin

// tieProcessToHost is a no-op: the service manager (systemd, the container
// runtime) stops the plugin processes together with SFTPGo.
func tieProcessToHost(_ int) error {
	return nil
}
