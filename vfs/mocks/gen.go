package mocks

import "github.com/aws/aws-sdk-go/service/s3/s3iface"

//go:generate mockgen -destination=s3_mock.go -package=mocks . S3API

type S3API interface {
	s3iface.S3API
}
