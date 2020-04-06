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

	"github.com/go-acme/lego/v3/certificate"
	"github.com/spf13/cobra"

	"salzr.com/certron/pkg/certron"
)

const (
	domainR = `^(?:[*a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
	emailR  = `^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`
)

type Options struct {
	Email         string
	Domain        string
	ProjectDir    string
	Force         bool
	AcceptedTerms bool
}

func RootCommand() (*cobra.Command, error) {
	o := newOptions()

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

	cmd.Flags().StringVarP(&o.Email, "email", "e", o.Email,
		"email is required to initialize the client")

	cmd.Flags().BoolVarP(&o.AcceptedTerms, "accept-terms", "a", o.AcceptedTerms,
		"you must accept the terms of service <https://letsencrypt.org/repository/> in order to generate the certificate")

	if err := cmd.MarkFlagRequired("email"); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (o *Options) Validate(args []string) error {
	o.Domain = args[0]

	re := regexp.MustCompile(domainR)
	if match := re.MatchString(o.Domain); match != true {
		return fmt.Errorf("domain arg value='%s' is not valid", o.Domain)
	}

	re = regexp.MustCompile(emailR)
	if match := re.MatchString(o.Email); match != true {
		return fmt.Errorf("email flag value='%s' is not valid", o.Email)
	}

	if !o.AcceptedTerms {
		return errors.New("you must accept the terms of service in order to use certron")
	}

	if _, err := os.Stat(o.ProjectDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(o.ProjectDir, 0700); err != nil {
				return err
			}
		}
	}

	return nil
}

func (o *Options) Run() error {
	var r *certificate.Resource

	c, err := certron.NewClient(o.Email)
	if err != nil {
		return err
	}

	fn := path.Join(o.ProjectDir, domainFileNameFmt(o.Domain))

	if !o.Force {
		r = isCached(fn)
	}

	if r == nil {
		r, err = c.GenerateCert(o.Domain, o.AcceptedTerms)
		if err != nil {
			return err
		}

		if err := cache(fn, r); err != nil {
			return err
		}
	}

	fmt.Printf("%s%s\n", r.Certificate, r.IssuerCertificate)

	return nil
}

func cache(filename string, r *certificate.Resource) error {
	j, err := json.Marshal(certron.NewResourceCache(r))
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, j, 0600)
}

func isCached(filename string) *certificate.Resource {
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

func newOptions() *Options {
	return &Options{
		ProjectDir: defaultProjectDir(),
	}
}

func domainFileNameFmt(d string) string {
	return strings.ReplaceAll(d, ".", "_") + ".json"
}
