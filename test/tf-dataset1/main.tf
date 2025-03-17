provider "vault" {
  address = "http://localhost:8200"
  token   = "myroot"
}

resource "vault_mount" "this" {
  path                      = "pki"
  type                      = "pki"
  max_lease_ttl_seconds     = "315569520"
  default_lease_ttl_seconds = "31556952"
}

resource "vault_pki_secret_backend_root_cert" "this" {
  backend              = vault_mount.this.path
  type                 = "internal"
  common_name          = "3scale Root CA"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "3scale"
  organization         = "Red Hat"
  ttl                  = "315569520" # 10 years
}

# Role for the VPN user certificates
resource "vault_pki_secret_backend_role" "client" {
  backend        = vault_mount.this.path
  name           = "client"
  ttl            = 94670856
  organization   = ["Red Hat"]
  ou             = ["3scale"]
  require_cn     = true
  allow_any_name = true
  key_usage      = ["DigitalSignature"]
  client_flag    = true
  server_flag    = false
}

# Role for VPN short lived certificates
resource "vault_pki_secret_backend_role" "client_48h" {
  backend        = vault_mount.this.path
  name           = "client-48h"
  ttl            = 172800
  organization   = ["Red Hat"]
  ou             = ["3scale"]
  require_cn     = true
  allow_any_name = true
  key_usage      = ["DigitalSignature"]
  client_flag    = true
  server_flag    = false
}


# Role to create server certificates in the same pki
# mount that should be ignored by ACPM
resource "vault_pki_secret_backend_role" "server" {
  backend         = vault_mount.this.path
  name            = "server"
  allowed_domains = ["some.random.domain"]
  require_cn      = true
  allow_any_name  = true
  key_usage       = ["DigitalSignature", "KeyEncipherment"]
  ext_key_usage   = ["ServerAuth"]
  client_flag     = false
  server_flag     = true
}

# Create a server certificate that should be ignored by ACPM
resource "vault_pki_secret_backend_cert" "server" {
  backend     = vault_mount.this.path
  name        = vault_pki_secret_backend_role.server.name
  common_name = "server.cvpn"
}

# This is to test approle auth without using the root token
resource "vault_policy" "acpm" {
  name   = "aws-cvpn-pki-manager"
  policy = <<EOT
path "${vault_mount.this.path}/*" {
  capabilities = ["read", "create", "update", "delete", "list"]
}
path "$utputs.data_mount_path}/data/users/*" {
  capabilities = ["read", "create", "update"]
}
EOT
}

resource "vault_auth_backend" "this" {
  type = "approle"
  tune {
    default_lease_ttl = "30m"
    max_lease_ttl     = "1h"
  }
}

resource "vault_approle_auth_backend_role" "acpm" {
  backend               = vault_auth_backend.this.path
  role_name             = "aws-cvpn-pki-manager"
  role_id               = "my-role-id"
  token_policies        = [vault_policy.acpm.name]
  secret_id_bound_cidrs = ["10.32.0.0/16"]
}

resource "vault_approle_auth_backend_role_secret_id" "acpm" {
  backend   = vault_auth_backend.this.path
  role_name = vault_approle_auth_backend_role.acpm.role_name
  secret_id = "my-secret-id"
}
