package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"salzr.com/certron/pkg/certron"
)

const (
	domainR = `^(?:[*a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
	emailR  = `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
)

type Options struct {
	email         string
	domain        string
	projectDir    string
	force         bool
	acceptedTerms bool

	resultWriter certron.ResultWriter

	toS3     bool
	S3bucket string
}

func RootCommand() (*cobra.Command, error) {
	o, err := newOptions()
	if err != nil {
		return nil, err
	}

	cmd := &cobra.Command{
		Use:   "certron domain",
		Short: "Certron ssl certificate generation utility",
		Long: `A simple way of generating FREE ssl certificates.
Resulting certs can be persisted in S3.
Certificate magic provided by the go-acme project <https://github.com/go-acme/lego>`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			handleErr(o.Validate(args))
			handleErr(o.Run())
		},
	}

	cmd.Flags().StringVarP(&o.email, "email", "e", o.email,
		"email is required to initialize the client")
	cmd.Flags().BoolVarP(&o.acceptedTerms, "accept-terms", "a", o.acceptedTerms,
		"you must accept the terms of service <https://letsencrypt.org/repository/> in order to generate the certificate")
	cmd.Flags().BoolVarP(&o.toS3, "to-s3", "", o.toS3,
		"uploads resulting certificate to Amazon's Simple Storage Solution")
	cmd.Flags().StringVarP(&o.S3bucket, "s3-bucket", "", o.S3bucket,
		"s3 bucket is the target bucket location where artifacts will be uploaded to")

	cmd.MarkFlagRequired("email")

	return cmd, nil
}

func (o *Options) Validate(args []string) error {
	o.domain = args[0]

	re := regexp.MustCompile(domainR)
	if match := re.MatchString(o.domain); match != true {
		return fmt.Errorf("domain arg value='%s' is not valid", o.domain)
	}

	re = regexp.MustCompile(emailR)
	if match := re.MatchString(o.email); match != true {
		return fmt.Errorf("email flag value='%s' is not valid", o.email)
	}

	if !o.acceptedTerms {
		return errors.New("you must accept the terms of service in order to use certron")
	}

	if _, err := os.Stat(o.projectDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(o.projectDir, 0700); err != nil {
				return err
			}
		}
	}

	if o.toS3 {
		if o.S3bucket == "" {
			return errors.New("--s3-bucket is required")
		}

		s3Writer, err := certron.NewS3Writer(certron.OptionS3BucketBase(o.S3bucket))
		if err != nil {
			return err
		}

		o.resultWriter = s3Writer
	}

	return nil
}

func (o *Options) Run() error {
	var r *certron.Result

	fn := path.Join(o.projectDir, domainFileNameFmt(o.domain))

	if !o.force {
		r = isCached(fn)
	}

	c, err := certron.NewClient(o.email, o.resultWriter)
	if err != nil {
		return err
	}

	if r == nil {
		r, err = c.GenerateCert(o.domain, o.acceptedTerms)
		if err != nil {
			return err
		}

		if err := cache(fn, r); err != nil {
			return err
		}
	}

	return c.Write(r)
}

func cache(filename string, r *certron.Result) error {
	j, err := json.Marshal(certron.NewResourceCache(r))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, j, 0600)
}

func isCached(filename string) *certron.Result {
	_, err := os.Stat(filename)
	if err != nil {
		return nil
	}

	j, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}

	r := &certron.ResourceCache{}
	if err := json.Unmarshal(j, r); err != nil {
		return nil
	}

	return r.ToResource()
}

func newOptions() (*Options, error) {
	writer, err := certron.NewDefaultWriter()
	if err != nil {
		return nil, err
	}

	return &Options{
		projectDir:   defaultProjectDir(),
		resultWriter: writer,
	}, nil
}

func domainFileNameFmt(d string) string {
	return strings.ReplaceAll(d, ".", "_") + ".json"
}
