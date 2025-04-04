client
dev tun
proto udp
remote {{.Username}}.{{.DNSName}} 443
remote-random-hostname
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
dhcp-option DOMAIN-SEARCH 3sca.net
cipher AES-256-GCM
verb 3
reneg-sec 0

<ca>
{{.CA}}
</ca>

<cert>
{{.Certificate}}
</cert>

<key>
{{.PrivateKey}}
</key>
