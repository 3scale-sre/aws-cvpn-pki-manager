package operations

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/hashicorp/vault/api"
)

// IssueCertificateRequest is the structure containing
// the required data to issue a new certificate
type IssueCertificateRequest struct {
	Client              *api.Client
	VaultPKIPaths       []string
	Username            string
	VaultPKIRole        string
	ClientVPNEndpointID string
	VaultKVPath         string
	CfgTplPath          string
	Temporary           bool
}

// IssueClientCertificate generates a new certificate for a given users, causing
// the revocation of other certificates emitted for that same user
func IssueClientCertificate(r *IssueCertificateRequest) (string, error) {

	// Init the struct to pass to the config.ovpn.tpl template
	data := struct {
		DNSName     string
		Username    string
		CA          string
		Certificate string
		PrivateKey  string
	}{
		Username: r.Username,
	}

	// Issue a new certificate
	payload := make(map[string]interface{})
	payload["common_name"] = r.Username
	crt, err := r.Client.Logical().Write(fmt.Sprintf("%s/issue/%s", r.VaultPKIPaths[len(r.VaultPKIPaths)-1], r.VaultPKIRole), payload)
	if err != nil {
		return "", err
	}
	data.Certificate = crt.Data["certificate"].(string)
	data.PrivateKey = crt.Data["private_key"].(string)
	log.Printf("Issued certificate %s", crt.Data["serial_number"])

	// Get the full CA chain of certificates from Vault
	// (the VPN config needs the full CA chain to the root CA in it)
	var caCerts []string
	for _, path := range r.VaultPKIPaths {
		req := r.Client.NewRequest("GET", fmt.Sprintf("/v1/%s/ca/pem", path))
		raw, err := r.Client.RawRequest(req)
		if err != nil {
			return "", err
		}
		defer raw.Body.Close()
		ca, err := ioutil.ReadAll(raw.Body)
		if err != nil {
			return "", err
		}
		caCerts = append(caCerts, string(ca))
	}
	data.CA = strings.Join(caCerts, "\n")

	// Get the VPN's DNS name from EC2 API
	svc := ec2.New(session.New())
	rsp, err := svc.DescribeClientVpnEndpoints(
		&ec2.DescribeClientVpnEndpointsInput{ClientVpnEndpointIds: aws.StringSlice([]string{r.ClientVPNEndpointID})})
	if err != nil {
		return "", err
	}
	// AWS returns the DNSName with an asterisk at the beginning, meaning that any subdomain
	// of the VPN's endpoint domain is valid. We need to strip this from the dns to use it
	// in the config
	data.DNSName = strings.SplitN(*rsp.ClientVpnEndpoints[0].DnsName, ".", 2)[1]

	// Resolve the config.ovpn.tpl template
	tpl, err := template.New(path.Base(r.CfgTplPath)).ParseFiles(r.CfgTplPath)
	if err != nil {
		return "", err
	}
	var config bytes.Buffer
	if err := tpl.Execute(&config, data); err != nil {
		return "", err
	}

	if !r.Temporary {
		// create/update the vpn config in the kv store
		payload["data"] = map[string]string{
			"content": config.String(),
		}
		_, err = r.Client.Logical().Write(fmt.Sprintf("%s/data/users/%s/config.ovpn", r.VaultKVPath, r.Username), payload)
		if err != nil {
			return "", err
		}

		// Call UpdateCRL to revoke all other certificates
		_, err = UpdateCRL(
			&UpdateCRLRequest{
				Client:              r.Client,
				VaultPKIPath:        r.VaultPKIPaths[len(r.VaultPKIPaths)-1],
				ClientVPNEndpointID: r.ClientVPNEndpointID,
			})

		if err != nil {
			return "", err
		}
	}

	return config.String(), nil
}

// revokeUserCertificates receives a list of certificates, sorted from oldest to newest, and revokes
// all but the latest if "revokeAll" is false and all of them if "revokeAll" is true.
func revokeUserCertificates(client *api.Client, pki string, crts []Certificate, revokeAll bool) error {

	for n, crt := range crts {
		// Do not revoke the last certificate
		if n == len(crts)-1 && !revokeAll {
			break
		}
		if !crt.Revoked {
			payload := make(map[string]interface{})
			payload["serial_number"] = crt.SerialNumber
			log.Printf("Revoked cert %s\n", crt.SerialNumber)
			client.Logical().Write(fmt.Sprintf("%s/revoke", pki), payload)
		}
	}

	return nil
}
