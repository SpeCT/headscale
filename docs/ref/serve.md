# Tailscale Serve and HTTPS certificates

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) lets a node expose a local service (a reverse
proxy, file server or static text) to the rest of the tailnet. Serve runs almost entirely on the node: the serve
configuration lives on the client, not on Headscale.

| Mode                                                 | Needs from Headscale                        | Status                                          |
| ---------------------------------------------------- | ------------------------------------------- | ----------------------------------------------- |
| `tailscale serve --http=...` (plain HTTP)            | MagicDNS                                    | Works out of the box                            |
| `tailscale serve` (HTTPS, the default) and `tailscale cert` | Per-node TLS certificates            | Requires the setup on this page                 |
| `tailscale funnel` (public internet)                 | Tailscale's ingress relays                  | **Not supported**, see [below](#funnel-is-not-supported) |

Plain HTTP serve only relies on [MagicDNS](dns.md). Serving over **HTTPS** needs a browser-trusted TLS certificate for
the node's MagicDNS name (`<node>.<base_domain>`), which the client obtains itself from
[Let's Encrypt](https://letsencrypt.org/) using an ACME **DNS-01** challenge. Headscale's role is to answer that
challenge.

## How certificate provisioning works

`tailscale cert` (used implicitly by `tailscale serve`) cannot use the HTTP-01 or TLS-ALPN-01 challenge types: those
require Let's Encrypt to connect **to the node**, and tailnet nodes are not publicly reachable. Only the DNS-01
challenge works, because it only requires a public DNS **TXT** record:

1. The node sees its FQDN advertised in `MapResponse.DNSConfig.CertDomains` and the `https` node capability, which
   unlocks `tailscale cert` and HTTPS serve in the client.
2. The node runs ACME against Let's Encrypt and generates the account key, the certificate key and the CSR locally.
   Headscale never sees the certificate or any private key.
3. To answer the DNS-01 challenge, the node sends the challenge value to Headscale's `/machine/set-dns` endpoint over
   the authenticated Noise connection. Headscale accepts it only for the node's own name.
4. Headscale publishes it as a TXT record at `_acme-challenge.<node>.<base_domain>` from a small embedded
   **authoritative DNS server** for `base_domain`.
5. Let's Encrypt resolves that record over the public internet, validates the challenge and issues the certificate.
   The node stores it and renews it automatically.

For step 5 to succeed, `base_domain` must be a **real, publicly delegated domain** whose DNS queries reach Headscale.

## Requirements

- [MagicDNS](dns.md) is enabled and `dns.base_domain` is set.
- `dns.base_domain` is a domain you own and can delegate (it cannot be a made-up name such as `example.internal`).
- Headscale is reachable from the public internet on the DNS port (UDP **and** TCP) configured below. The existing
  HTTP reverse proxy cannot carry this traffic. Binding a privileged port such as `:53` requires
  `CAP_NET_BIND_SERVICE` or running as root.
- The nodes can reach Let's Encrypt (`acme-v02.api.letsencrypt.org`) over HTTPS.

## Configuration

```yaml title="config.yaml"
server_url: https://headscale.example.com

dns:
  magic_dns: true
  base_domain: ts.example.com

  https_certs:
    # Enable per-node HTTPS certificate provisioning.
    enabled: true

    # Address the embedded authoritative DNS server listens on (UDP and TCP)
    # for ACME challenge queries from public resolvers.
    listen_addr: ":53"

    # Public hostname of this authoritative DNS server, used in SOA and NS
    # answers. Defaults to the hostname of server_url.
    nameserver: headscale.example.com
```

`nameserver` should be a name **outside** `base_domain` that already resolves to Headscale's public IP address, such
as the control server hostname. A name inside `base_domain` (for example `ns.ts.example.com`) also works but then the
parent zone must publish glue `A`/`AAAA` records for it, because Headscale does not serve address records.

## Delegate the zone

Headscale only answers the `_acme-challenge` TXT lookups and the zone's SOA/NS records for `base_domain`. Every other
in-zone query (including `A`, `AAAA` and `CAA`) gets an empty NOERROR answer, and queries outside the zone are refused.
Node addresses stay internal to the tailnet via MagicDNS and are intentionally **not** published.

At your registrar or in the parent DNS zone, delegate `base_domain` to Headscale by pointing its `NS` record at the
configured `nameserver`. For `base_domain: ts.example.com` and `nameserver: headscale.example.com`:

```dns
ts.example.com.         NS   headscale.example.com.
headscale.example.com.  A    203.0.113.10        ; Headscale's public IP, usually already present
```

Do not publish a `DS` record for `base_domain`: the embedded server does not sign the zone, and a `DS` record would
make validating resolvers such as Let's Encrypt's treat every answer as bogus. If the parent zone carries `CAA`
records, make sure they permit `letsencrypt.org`.

Verify the delegation before enabling the feature on nodes:

```console
$ dig +short NS ts.example.com
headscale.example.com.
$ dig +norec @headscale.example.com SOA ts.example.com
```

## Usage

Once enabled and delegated, use Tailscale's CLI on a node as usual:

```console
# Obtain a certificate for this node's MagicDNS name
$ sudo tailscale cert node.ts.example.com

# Reverse-proxy a local service over HTTPS on port 443 (tailnet only)
$ tailscale serve --bg 8080

# Serve over plain HTTP (works without https_certs)
$ tailscale serve --http=80 --bg 8080
```

Certificates are requested lazily on the first HTTPS connection and renewed by the client. Only nodes that are
allowed to reach the serving node by the [policy](policy.md) can connect; a certificate does not grant access.

## Privacy and security notes

- **Private reachability.** Serve only listens on the node's tailnet address. The service is not reachable from the
  public internet, and ACLs/grants restrict which tailnet users and devices may connect.
- **Private address resolution.** Node `A`/`AAAA` records are only resolvable through MagicDNS. Public DNS never
  learns the tailnet IP of a node.
- **The hostname is public.** Let's Encrypt records every issued certificate in public Certificate Transparency logs,
  so the full node name (`node.ts.example.com`) becomes publicly visible, exactly as with Tailscale's own HTTPS
  feature. Use non-sensitive node and base domain names. If the hostname itself must stay secret, use a private CA
  instead; that is a different setup.
- A node may only publish the ACME challenge record for **its own** FQDN. `/machine/set-dns` refuses other names,
  wildcards, non-TXT records, oversized values, unknown nodes and nodes whose key has expired.
- Challenge values live only in memory for ten minutes after they were last set and are dropped on restart, so no
  challenge data lingers.
- Certificate and ACME account private keys are generated and stored on the node. Headscale never receives them.
- The metric `headscale_acme_set_dns_requests_total{status}` counts accepted (`ok`) and rejected challenge
  publications and requests made while the feature is `disabled`.

## Funnel is not supported

[Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel) exposes a node's service to the public
internet through Tailscale-operated ingress relays. Headscale cannot provide that infrastructure, so Funnel is not
supported. See [#1040](https://github.com/juanfont/headscale/issues/1040).
