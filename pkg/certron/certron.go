package certron

import (
	"archive/zip"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	writer ResultWriter
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

type Result struct {
	certificate *certificate.Resource
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

func NewClient(email string, w ResultWriter) (*Client, error) {
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

	return &Client{client: c, user: u, writer: w}, nil
}

func (c *Client) GenerateCert(domain string, confirm bool) (*Result, error) {
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

	resource, err := c.client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}

	return &Result{resource}, nil
}

func (c *Client) Write(r *Result) error {
	return c.writer.Write(r)
}

// TODO: Wrap resource in a result type
// implement String and ToZip methods.
func (r ResourceCache) ToResource() *Result {
	resource := &certificate.Resource{
		Domain:            r.Domain,
		CertURL:           r.CertURL,
		CertStableURL:     r.CertStableURL,
		PrivateKey:        r.PrivateKey,
		Certificate:       r.Certificate,
		IssuerCertificate: r.IssuerCertificate,
		CSR:               r.CSR,
	}

	return &Result{resource}
}

func NewResourceCache(r *Result) *ResourceCache {
	return &ResourceCache{
		Domain:            r.certificate.Domain,
		CertURL:           r.certificate.CertURL,
		CertStableURL:     r.certificate.CertStableURL,
		PrivateKey:        r.certificate.PrivateKey,
		Certificate:       r.certificate.Certificate,
		IssuerCertificate: r.certificate.IssuerCertificate,
		CSR:               r.certificate.CSR,
	}
}

func (r *Result) String() string {
	s := `
CERTIFICATE, CHAIN AND PRIVATE KEY
----------------------------------

%s
%s
`
	return fmt.Sprintf(s, r.certificate.Certificate, r.certificate.PrivateKey)
}

// ToFile generates a temporary compressed file containing the
// certificates, certificate chain, and its private key.
func (r *Result) ToFile() (string, error) {
	certs := decodeBundle(r.certificate.Certificate)

	dir, err := ioutil.TempDir("", "certron-*")
	if err != nil {
		return "", err
	}

	if err := ioutil.WriteFile(filepath.Join(dir, "cert.pem"), certs[0], 0444); err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "chain.pem"), certs[1], 0444); err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "privKey.pem"), r.certificate.PrivateKey, 0444); err != nil {
		return "", err
	}

	t := time.Now()
	zipName := fmt.Sprintf("%s.zip", t.Format("20060102T150405"))
	zipFile, err := os.Create(filepath.Join(dir, zipName))
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	baseDir := filepath.Base(dir)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		fileName := strings.TrimPrefix(path, dir)
		if filepath.Base(fileName) == zipName {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, fileName)
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		return "", err
	}

	return filepath.Join(dir, zipName), nil
}

func decodeBundle(bundle []byte) [][]byte {
	var cert *pem.Block

	certificates := make([][]byte, 0)
	for {
		cert, bundle = pem.Decode(bundle)
		if cert == nil {
			break
		}
		if cert.Type == "CERTIFICATE" {
			certificates = append(certificates, pem.EncodeToMemory(cert))
		}
	}

	return certificates
}
