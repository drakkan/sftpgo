package fsmeta

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/drakkan/sftpgo/metrics"
)

type S3API interface {
	HeadObjectWithContext(ctx aws.Context, input *s3.HeadObjectInput, opts ...request.Option) (*s3.HeadObjectOutput, error)
}

type s3Provider struct {
	s3     S3API
	bucket string
}

func NewS3Provider(s3 S3API, Bucket string) Getter {
	return &s3Provider{
		s3:     s3,
		bucket: Bucket,
	}
}

func (s *s3Provider) Get(ctx context.Context, Key Key) (Meta, error) {
	Head, err := s.s3.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(Key.Path),
	})
	metrics.S3HeadObjectCompleted(err)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == s3.ErrCodeNoSuchKey {
				return Meta{
					Key:          Key,
					LastModified: Key.StoreTime,
				}, nil
			}
		}
		return Meta{}, err
	}

	Helper := MetaHelper(Head.Metadata)
	FSTime, err := Helper.GetTime(S3MetaKey)
	if err == ErrMetaKeyNotFound {
		return Meta{
			Key:          Key,
			LastModified: Key.StoreTime,
		}, nil
	}
	return Meta{
		Key:          Key,
		LastModified: FSTime,
	}, nil
}
