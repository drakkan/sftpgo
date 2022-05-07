//go:build !awscontainer
// +build !awscontainer

package service

func registerAWSContainer(disableAWSInstallationCode bool) error {
	return nil
}
