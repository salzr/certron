package certron

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type ResultWriter interface {
	Write(r *Result) error
}

type DefaultWriter struct{}

func NewDefaultWriter() (ResultWriter, error) {
	return &DefaultWriter{}, nil
}

func (w DefaultWriter) Write(r *Result) error {
	_, err := fmt.Println(r)
	return err
}

type S3Writer struct {
	bucket   string
	uploader *s3manager.Uploader
	client   *s3.S3
}

func NewS3Writer(opts ...s3option) (ResultWriter, error) {
	sess := session.Must(session.NewSession())

	w := &S3Writer{
		client:   s3.New(sess),
		uploader: s3manager.NewUploader(sess),
	}

	for _, opt := range opts {
		opt(w)
	}

	return w, nil
}

type s3option func(w *S3Writer)

func OptionS3BucketBase(name string) s3option {
	return func(w *S3Writer) {
		w.bucket = name
	}
}

func (w S3Writer) Write(r *Result) error {
	file, err := r.ToFile()
	if err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Dir(file))

	f, err := os.Open(file)
	if err != nil {
		return err
	}

	bucket := aws.String(w.bucket)

	_, err = w.client.HeadBucket(&s3.HeadBucketInput{
		Bucket: bucket,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return aerr
		} else {
			return err
		}
	}

	domain := strings.TrimPrefix(r.certificate.Domain, "*.")
	key := filepath.Join(domain, filepath.Base(file))

	_, err = w.uploader.Upload(&s3manager.UploadInput{
		Bucket: bucket,
		Key:    aws.String(key),
		Body:   f,
	})

	return err
}
