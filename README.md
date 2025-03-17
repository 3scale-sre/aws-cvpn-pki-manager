# AWS Client VPN PKI Manager (ACPM)

ACPM is a small application to help you manage the Public Key Infrastruture (certificates) for your AWS Client VPN setup.

## Why

Clint VPN is an AWS service that allows you to deploy a OpenVPN compatible client-to-site VPN without the hassle of having to manage any servers. But you are still left to manage your own PKI to grant your users access to the VPN (unluss you use authentication integrated with an Active Directory). Managing a PKI is a complex task, as you have to manage a CA, server certificates, client certificates and revocation lists. The recommended approach pointed at y the AWS documentation is using the `easy-rsa` project, but that requires a server to be executed and a place to persist and share the PKI status.

This project leverages Hashicop's Vault PKI secret engine to use it as the storage for all your certificates. By exposing a very simple remote API gives you access to all the specific management tasks required to handle the PKI:

* Issue new certificates for new or existent users
* Automatically generate the complete VPN config file and store it in Vault for the VPN user to have it available there
* List the current users and their certificates
* Completely revoke a user
* Get the Client Revocation List (CRL)
* Update the Client Revocation List in your AWS Client VPN

## How it works

This project works under the following premises:

* A Hashicorp Vault installation, with the following secret backends, exists:
  * A PKI backend that will be used to store the CA, server certificate, client certificates and CRL
  * A kv2 (key value v2) backend exists to store the users OpenVPN config file
* An AWS Client VPN endpoint exists, configured with the CA and server certificate from the Vault PKI backend
* Each user will only have one valid certificate at a given time. This means that when a new certificate is issued for an existent client, all other certificates that the user might have will be revoked, and only the new one will be valid from that moment on.


## Vault permissions

The following vault policy is required for ACPM:

```
path "cvpn-pki/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "secret/data/users/*" {
  capabilities = ["read", "create", "update"]
}

```

You need to chaned the paths accordingly if not using the defaults values for the Vault backends paths.

There are currently to methods to configure access to the vault server: token or approle. Whichever you use, it need to have the previous policy attached.

### Token

Simply generate a Vault token with at least the level of permissions describe in previous policy. You could also directly use a Vault's root token, but it is not recommended ouside of development purposes.
To use the token just launch the server with the `--vault-auth-token <your-tokeb>`.

### Approle

ACPM can use the Approle Vault's auth backend to dinamycally generate tokens. You need to:
* enable the approle auth backend method in your Vault server
* create a role with the required policy associated to it
* create a secret-id from that role

Configure the ACPM server with the flags `--vault-auth-approle-role-id`, `--vault-auth-approle-secret-id` so it can start requesting tokens using the provided role and secret.

Check Vault's [documentation on the Approle auth backend](https://www.vaultproject.io/docs/auth/approle/) for more information.

## AWS API permissions

ACPM uses the official golang AWS SDK to interact with AWS APIs, so you can use any auth [method available in the SDK](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html).

The AWS credentials need `ec2:ImportClientVpnClientCertificateRevocationList`, `ec2:ExportClientVpnClientCertificateRevocationList` and `ec2:DescribeClientVpnEndpoints` on the Client VPN endpoint. An example policy:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "ec2:ImportClientVpnClientCertificateRevocationList",
                "ec2:ExportClientVpnClientCertificateRevocationList",
                "ec2:DescribeClientVpnEndpoints"
            ],
            "Resource": "*"
        }
    ]
}
```

NOTE: seems like Client VPN endpoints don't support resource scoped permissions. If you find how to do it, open an issue! :)

## ACPM Authentication

By default, ACPM does not have authentication and the API is available for anyone that has network access to the server endpoint. It is possible to set up authentication but currently only GitHub personal access tokens auth method is available.

To enable and configure GitHub personal access tokens auth to ACPM use the command line options `--auth-github-*`. Check the list of command line options below.

To use GitHub personal access tokens just use your token as a Bearer token in the `Authorization` http header of the request. For example:

```bash
curl -H "Authorization: Bearer <github-personal-access-token>" http://localhost:8080/users
```

## Command Line flags and options

| Flag                              | Envvar                               | Default                   | Required | Description                                                                                                                                                                   |
|-----------------------------------|--------------------------------------|---------------------------|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --client-vpn-endpoint-id          | ACPM_CLIENT_VPN_ENDPOINT_ID          | N/A                       | yes      | The Id of the AWS Client VPN endpoint                                                                                                                                         |
| --config-template-path            | ACPM_CONFIG_TEMPLATE_PATH            | "./config.ovpn.tpl"       | no       | The location of the template to generate the OpenVPN config files for the users                                                                                               |
| --port                            | ACPM_PORT                            | "8080"                    | no       | The port to listen to                                                                                                                                                         |
| --vault-pki-paths                 | ACPM_VAULT_PKI_PATHS                 | ["cvpn-pki" , "root-pki"] | no       | The list of Vault PKI backends that hold each of the intermediate CAs up until the root CA. Must be ordered from lowest level CA to Root CA                                   |
| --vault-kv-path                   | ACPM_VAULT_KV_PATH                   | "secret"                  | no       | The path of the kv backend that will be used to store each user's OpenVPN config                                                                                              |
| --vault-client-certificate-role   | ACPM_VAULT_CLIENT_CERTIFICATE_ROLE   | "client"                  | no       | The role in the PKI backend (the one corresponding to the lowest level CA) used to generate new client certificates                                                           |
| --vault-auth-token                | ACPM_VAULT_AUTH_TOKEN                | N/A                       | no       | The token to authenticate to the Vault server                                                                                                                                 |
| --vault-auth-approle-backend-path | ACPM_VAULT_AUTH_APPROLE_BACKEND_PATH | authrole                  | no       | When the approle auth backend to authenticate to Vault, the path of the approle backend                                                                                       |
| --vault-auth-approle-role-id      | ACPM_VAULT_AUTH_APPROLE_ROLE_ID      | N/A                       | no       | When the approle auth backend to authenticate to Vault, the ID of the role to use                                                                                             |
| --vault-auth-approle-secret-id    | ACPM_VAULT_AUTH_APPROLE_SECRET_ID    | N/A                       | no       | When the approle auth backend to authenticate to Vault, the ID of the secret to be used                                                                                       |
| --auth-github-org                 | ACPM_AUTH_GITHUB_ORG                 | N/A                       | no       | This flag activates GitHub authentication with personal access token to the ACPM server. All GitHub tokens that are members of the org passed as value will be granted access |
| --auth-github-teams               | ACPM_AUTH_GITHUB_TEAMS               | N/A                       | no       | All GitHub tokens that are members of the team passed as value will be granted access                                                                                         |
| --auth-github-users               | ACPM_AUTH_GITHUB_USERS               | N/A                       | no       | All GitHub tokens that match any of the users in the list passed as value will be granted access                                                                              |

## Usage


#### API operations

##### List users

List all the users and all the certificates binded to them. Just a single certificate is valid for a user at a given time. If the user has been revoked, no valid certificates will be shown for that user.

```bash
▶ curl -s http://localhost:8080/users
```

##### Get Client Revokation List (CRL)

Retrieves the CRL from the Vault PKI storage backend.

```bash
▶ curl -s http://localhost:8080/crl
```

The CRL can be inspected with openssl cli tool.

```bash
curl -s http://localhost:8080/crl | jq -r .crl | openssl crl -in - -text -noout
```

##### Update Client Revokation List (CRL)

Retrieves the CRL from Vault's PKI secret engine and uploads it to the Client VPN endpoint, to keep them in sync. VPN admins are typically not required to call this endpoint:
* Any other operation that triggers revocation of client certificates triggers this action, to keep the CRL always in sync.
* There is a daily operation to rotate and resync the CRL to avoid CRL expiration. Just make sure the duration of your CRL is at least 24h.

The update endpoint won't do anything if the CRL is already in sync

##### Rotate Client Revokation List (CRL)

Calls the /pki/crl/rotate Vault endpoint to renew the CRL. The performs an Update Client Revokation List operation. This operation is run daily by acpm, so it is not required that admins call this endpoint manually.

```bash
▶ curl -s http://localhost:8080/crl/rotate -XPOST
```

##### Issue a new certificate

Issues a new certificate for the given GitHub user. The name passed in the request must match the name of the user in GitHub. The resulting certificate is stored in Vault PKI engine, and the user config is stored in Vault's kv2 (key-value) engine, under the path `/secret/<config-template-path>/<name>/config.ovpn`.

```bash
▶ curl http://localhost:8080/issue/user -XPOST
```

When a new certificate is issued for a user, all the other certificates (if any) that were previously issued for that same user are revoked by ACPM and the CRL gets updated in the Client VPN endpoint.

##### Revoke a user

This operation revokes all the certificates for a given user:

```bash
▶ curl http://localhost:8080/revoke/roivaz -XPOST
```

New certificates can still be issued for this user if required.