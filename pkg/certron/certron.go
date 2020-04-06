package certron

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

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

type ResourceCache struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"privateKey"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuerCertificate"`
	CSR               []byte `json:"csr"`
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

func (c *Client) GenerateCert(domain string, confirm bool) (*certificate.Resource, error) {
	p, err := dns.NewDNSChallengeProviderByName("route53")
	if err != nil {
		return nil, err
	}

	if err := c.client.Challenge.SetDNS01Provider(p); err != nil {
		return nil, err
	}

	r, err := c.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: confirm})
	if err != nil {
		return nil, err
	}
	c.user.Registration = r

	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	return c.client.Certificate.Obtain(req)
}

func (r ResourceCache) ToResource() *certificate.Resource {
	return &certificate.Resource{
		Domain:            r.Domain,
		CertURL:           r.CertURL,
		CertStableURL:     r.CertStableURL,
		PrivateKey:        r.PrivateKey,
		Certificate:       r.Certificate,
		IssuerCertificate: r.IssuerCertificate,
		CSR:               r.CSR,
	}
}

func NewResourceCache(r *certificate.Resource) *ResourceCache {
	return &ResourceCache{
		Domain:            r.Domain,
		CertURL:           r.CertURL,
		CertStableURL:     r.CertStableURL,
		PrivateKey:        r.PrivateKey,
		Certificate:       r.Certificate,
		IssuerCertificate: r.IssuerCertificate,
		CSR:               r.CSR,
	}
}
