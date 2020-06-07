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
	"github.com/spf13/viper"

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

	S3       bool
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
		Run: func(cmd *cobra.Command, args []string) {
			handleErr(o.Validate(args))
			handleErr(o.Run())
		},
	}

	cmd.Flags().String("email", o.email,
		"email is required to initialize the client")
	cmd.Flags().Bool("accept-terms", o.acceptedTerms,
		"you must accept the terms of service <https://letsencrypt.org/repository/> in order to generate the certificate")
	cmd.Flags().Bool("to-s3", o.S3,
		"uploads resulting certificate to Amazon's Simple Storage Solution")
	cmd.Flags().String("s3-bucket", o.S3bucket,
		"s3 bucket is the target bucket location where artifacts will be uploaded to")

	viper.BindPFlag("email", cmd.Flags().Lookup("email"))
	viper.BindPFlag("accept_terms", cmd.Flags().Lookup("accept-terms"))
	viper.BindPFlag("to_s3", cmd.Flags().Lookup("to-s3"))
	viper.BindPFlag("s3_bucket", cmd.Flags().Lookup("s3-bucket"))

	return cmd, nil
}

// TODO: Argument or HOST are required
// TODO: Set option
func (o *Options) Validate(args []string) error {
	setOptionsFromEnv(o)

	if o.domain == "" && len(args) != 0 {
		o.domain = args[0]
	}
	if o.domain == "" {
		return fmt.Errorf("CERTRON_DOMAIN or certron <domain> argument must be set")
	}

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

	if o.S3 {
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

func setOptionsFromEnv(o *Options) {
	o.domain = viper.GetString("DOMAIN")
	o.email = viper.GetString("EMAIL")
	o.acceptedTerms = viper.GetBool("ACCEPT_TERMS")

	o.S3 = viper.GetBool("S3")
	o.S3bucket = viper.GetString("S3_BUCKET")
}
