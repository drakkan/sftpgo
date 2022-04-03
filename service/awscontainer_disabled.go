//go:build !awscontainer
// +build !awscontainer

package service

func registerAWSContainer() error {
	return nil
}
