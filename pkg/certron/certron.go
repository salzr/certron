package certron

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns"
	"github.com/go-acme/lego/v3/registration"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type Client struct {
	user   *User
	client *lego.Client
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewClient(email string) (*Client, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	u := &User{
		Email: email,
		key:   k,
	}

	cfg := lego.NewConfig(u)
	cfg.CADirURL = lego.LEDirectoryProduction
	cfg.Certificate.KeyType = certcrypto.RSA2048
	c, err := lego.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &Client{client: c, user: u}, nil
}

func (c *Client) GenerateCert(domain string, confirm bool) error {
	p, err := dns.NewDNSChallengeProviderByName("route53")
	if err != nil {
		return err
	}

	if err := c.client.Challenge.SetDNS01Provider(p); err != nil {
		return err
	}

	r, err := c.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: confirm})
	if err != nil {
		return err
	}
	c.user.Registration = r

	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certs, err := c.client.Certificate.Obtain(req)
	if err != nil {
		return err
	}

	fmt.Printf("%#v\n", certs)

	return nil
}
