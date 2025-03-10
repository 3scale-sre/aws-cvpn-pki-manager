package operations

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

// ListUsersRequest is the structure containing
// the required data to issue a new certificate
type ListUsersRequest struct {
	Client              *api.Client
	VaultPKIPath        string
	ClientVPNEndpointID string
}

// ListUsers retrieves the list of all Client VPN users and certificates
func ListUsers(r *ListUsersRequest) (map[string][]Certificate, error) {
	users := map[string][]Certificate{}

	secret, err := r.Client.Logical().List(fmt.Sprintf("%s/certs", r.VaultPKIPath))
	if err != nil {
		return nil, err
	}

	// Get the updated CRL
	crl, err := GetCRL(
		&GetCRLRequest{
			Client:       r.Client,
			VaultPKIPath: r.VaultPKIPath,
		})
	if err != nil {
		return nil, err
	}

	for _, key := range secret.Data["keys"].([]interface{}) {
		secret, err := r.Client.Logical().Read(fmt.Sprintf("%s/cert/%s", r.VaultPKIPath, key))
		if err != nil {
			return nil, err
		}
		rawCert := secret.Data["certificate"].(string)
		block, _ := pem.Decode([]byte(rawCert))
		if block == nil {
			return nil, errors.Wrapf(err, "failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse certificate")
		}

		if cert.IsCA || isServerCertificate(cert) {
			// Do not list the CA
			continue
		}

		notBefore := cert.NotBefore.Local()
		notAfter := cert.NotAfter.Local()
		serial := strings.TrimSpace(getHexFormatted(cert.SerialNumber.Bytes()))
		revoked, err := isRevoked(serial, crl)
		if err != nil {
			return nil, err
		}

		username := strings.Split(cert.Subject.CommonName, "@")[0]
		users[username] = append(users[username], Certificate{
			serial,
			cert.Issuer.CommonName,
			cert.Subject.CommonName,
			notBefore,
			notAfter,
			revoked,
			rawCert,
		})
	}

	// Sort the arrays but notBefore date (which should be the
	// date the certificate was emitted at)
	for _, crts := range users {
		sort.Slice(crts, func(i, j int) bool {
			return crts[i].NotBefore.Before(crts[j].NotBefore)
		})
	}

	return users, nil
}

// RevokeUserRequest is the structure containing
// the required data to issue a new certificate
type RevokeUserRequest struct {
	Client              *api.Client
	VaultPKIPath        string
	Username            string
	ClientVPNEndpointID string
}

// RevokeUser revokes all the issued certificates for a given user
func RevokeUser(r *RevokeUserRequest) error {

	// Get the list of users
	users, err := ListUsers(
		&ListUsersRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})
	if err != nil {
		return err
	}

	err = revokeUserCertificates(r.Client, r.VaultPKIPath, users[r.Username], true)
	if err != nil {
		return err
	}

	// Call UpdateCRL to revoke all other certificates
	_, err = UpdateCRL(
		&UpdateCRLRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPath,
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		})
	if err != nil {
		return err
	}

	return nil
}

func getHexFormatted(buf []byte) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprintf(&ret, "-")
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

func isRevoked(serial string, crl []byte) (bool, error) {
	parsed, err := x509.ParseCRL(crl)
	if err != nil {
		return false, err
	}
	list := parsed.TBSCertList.RevokedCertificates
	for _, crt := range list {
		if serial == strings.TrimSpace(getHexFormatted(crt.SerialNumber.Bytes())) {
			return true, nil
		}
	}
	return false, nil
}

func isServerCertificate(cert *x509.Certificate) bool {
	flag := false
	for _, use := range cert.ExtKeyUsage {
		if use == x509.ExtKeyUsageServerAuth {
			flag = true
		}
	}
	return flag
}
