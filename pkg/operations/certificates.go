package operations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"text/template"

	"github.com/3scale/aws-cvpn-pki-manager/pkg/config"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/go-logr/logr"

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
}

// IssueClientCertificate generates a new certificate for a given users, causing
// the revocation of other certificates emitted for that same user
func IssueClientCertificate(r *IssueCertificateRequest, logger logr.Logger) (string, error) {

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
		logger.Error(err, "error issuing new certificate")
		return "", err
	}
	data.Certificate = crt.Data["certificate"].(string)
	data.PrivateKey = crt.Data["private_key"].(string)
	logger.Info(fmt.Sprintf("Issued certificate %s", crt.Data["serial_number"]))

	// Get the full CA chain of certificates from Vault
	// (the VPN config needs the full CA chain to the root CA in it)
	var caCerts []string
	for _, path := range r.VaultPKIPaths {
		ctx, cancel := context.WithTimeout(context.Background(), config.VaultApiTimeout)
		defer cancel()
		rsp, err := r.Client.Logical().ReadRawWithContext(ctx, fmt.Sprintf("/%s/ca/pem", path))
		if err != nil {
			logger.Error(err, "unable to retrieve CA for "+path)
			return "", err
		}
		defer rsp.Body.Close()
		ca, err := io.ReadAll(rsp.Body)
		if err != nil {
			logger.Error(err, fmt.Sprintf("error while reading /v1/%s/ca/pem", path))
			return "", err
		}
		caCerts = append(caCerts, string(ca))
	}
	data.CA = strings.Join(caCerts, "\n")

	// Get the VPN's DNS name from EC2 API
	ctx, cancel := context.WithTimeout(context.Background(), config.AwsApiTimeout)
	defer cancel()
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Error(err, "unable to load AWS EC2 client")
		return "", err
	}
	svc := ec2.NewFromConfig(cfg)
	rsp, err := svc.DescribeClientVpnEndpoints(ctx,
		&ec2.DescribeClientVpnEndpointsInput{ClientVpnEndpointIds: []string{r.ClientVPNEndpointID}})
	if err != nil {
		logger.Error(err, "error in AWS call to describeClientVpnEndpointsInput")
		return "", err
	}
	// AWS returns the DNSName with an asterisk at the beginning, meaning that any subdomain
	// of the VPN's endpoint domain is valid. We need to strip this from the dns to use it
	// in the config
	data.DNSName = strings.SplitN(*rsp.ClientVpnEndpoints[0].DnsName, ".", 2)[1]

	// Resolve the config.ovpn.tpl template
	tpl, err := template.New(path.Base(r.CfgTplPath)).ParseFiles(r.CfgTplPath)
	if err != nil {
		logger.Error(err, "unable to load config.ovpn template")
		return "", err
	}
	var config bytes.Buffer
	if err := tpl.Execute(&config, data); err != nil {
		logger.Error(err, "unable to resolve config.ovpn template")
		return "", err
	}

	// create/update the vpn config in the kv store
	payload["data"] = map[string]string{
		"content": config.String(),
	}
	_, err = r.Client.Logical().Write(fmt.Sprintf("%s/data/users/%s/config.ovpn", r.VaultKVPath, r.Username), payload)
	if err != nil {
		logger.Error(err, fmt.Sprintf("unable to update %s/data/users/%s/config.ovpn in KV2 store", r.VaultKVPath, r.Username))
		return "", err
	}

	// Call UpdateCRL to revoke all other certificates
	_, err = UpdateCRL(
		&UpdateCRLRequest{
			Client:              r.Client,
			VaultPKIPath:        r.VaultPKIPaths[len(r.VaultPKIPaths)-1],
			ClientVPNEndpointID: r.ClientVPNEndpointID,
		}, logger)

	if err != nil {
		return "", err
	}

	return config.String(), nil
}

// revokeUserCertificates receives a list of certificates, sorted from oldest to newest, and revokes
// all but the latest if "revokeAll" is false and all of them if "revokeAll" is true.
func revokeUserCertificates(client *api.Client, pki string, crts []Certificate, revokeAll bool, logger logr.Logger) error {

	for n, crt := range crts {
		// Do not revoke the last certificate
		if n == len(crts)-1 && !revokeAll {
			break
		}
		if !crt.Revoked {
			payload := make(map[string]interface{})
			payload["serial_number"] = crt.SerialNumber
			if _, err := client.Logical().Write(fmt.Sprintf("%s/revoke", pki), payload); err != nil {
				logger.Error(err, fmt.Sprintf("unable to revoke certificate %s/%s", crt.SubjectCN, crt.SerialNumber))
				return err
			}
			logger.Info(fmt.Sprintf("Revoked cert %s/%s\n", crt.SubjectCN, crt.SerialNumber))

		}
	}

	return nil
}
