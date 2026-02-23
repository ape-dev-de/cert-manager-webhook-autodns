# cert-manager-webhook-autodns

A [cert-manager](https://cert-manager.io/) webhook solver for [AutoDNS](https://en.autodns.com/) (InterNetX) DNS-01 challenges.

Rewritten from [derJD/cert-manager-webhook-autodns](https://github.com/derJD/cert-manager-webhook-autodns) with updated dependencies, Secret-based credential handling, and hardened container security.

## What it does

Handles DNS-01 ACME challenges by creating/removing TXT records via the [AutoDNS API](https://help.internetx.com/display/APIJSONEN). This allows cert-manager to issue certificates (including wildcards) for domains managed by InterNetX/AutoDNS without needing HTTP-01 (no port 80 required).

## Install

### 1. Create the credentials Secret

```bash
kubectl -n cert-manager create secret generic autodns-credentials \
  --from-literal=username=YOUR_USER_ID \
  --from-literal=password=YOUR_PASSWORD \
  --from-literal=context=4
```

| Field      | Description                                      |
|------------|--------------------------------------------------|
| `username` | AutoDNS user ID                                  |
| `password` | AutoDNS password                                 |
| `context`  | `4` for live, `1` for demo (default: `4`)        |

### 2. Deploy the webhook

```bash
helm install cert-manager-webhook-autodns \
  --namespace cert-manager \
  deploy/cert-manager-webhook-autodns
```

Or with Flux HelmRelease pointing to this repo's Helm chart.

### 3. Create a ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-dns
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-dns-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.ape-dev.de
            solverName: autodns
            config:
              secretRef: autodns-credentials
              secretNamespace: cert-manager
              # url: https://api.autodns.com/v1   # default
              # nameServer: a.ns14.net             # default
              # zone: example.com                  # auto-detected from cert
```

### 4. Request a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: my-namespace
spec:
  secretName: my-cert-tls
  issuerRef:
    name: letsencrypt-dns
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"
```

## Configuration

### Solver config fields

| Field             | Required | Default                        | Description                              |
|-------------------|----------|--------------------------------|------------------------------------------|
| `secretRef`       | No       | `autodns-credentials`          | Name of the K8s Secret with credentials  |
| `secretNamespace` | No       | Challenge namespace            | Namespace of the credentials Secret      |
| `url`             | No       | `https://api.autodns.com/v1`   | AutoDNS API endpoint                     |
| `nameServer`      | No       | `a.ns14.net`                   | Nameserver for zone updates              |
| `zone`            | No       | Auto-detected                  | DNS zone (e.g. `example.com`)            |

### Helm values

| Value                          | Default                                                      |
|--------------------------------|--------------------------------------------------------------|
| `groupName`                    | `acme.ape-dev.de`                                            |
| `certManager.namespace`        | `cert-manager`                                               |
| `certManager.serviceAccountName` | `cert-manager`                                             |
| `autodns.secretName`           | `autodns-credentials`                                        |
| `image.repository`             | `ghcr.io/ape-dev-de/cert-manager-webhook-autodns`            |
| `image.tag`                    | `v1.0.0`                                                     |

## How it works

The webhook implements cert-manager's DNS-01 solver interface:

- **Present**: `PATCH /zone/{zone}/{nameserver}` with `adds: [{name, value, type: "TXT", ttl: 60}]`
- **CleanUp**: `PATCH /zone/{zone}/{nameserver}` with `removes: [{name, value, type: "TXT", ttl: 60}]`

Authentication uses HTTP Basic Auth with `X-Domainrobot-Context` header, credentials read from a Kubernetes Secret (never inline in the Issuer).

## Security

- Credentials stored in K8s Secret, never in Issuer/ClusterIssuer config
- RBAC scoped to single named Secret (no cluster-wide secrets access)
- Container runs as non-root (UID 65534) with read-only root filesystem
- No privileged capabilities
- Image built from source via GitHub Actions (auditable supply chain)

## Development

```bash
# Build locally
CGO_ENABLED=0 go build -o webhook .

# Build Docker image
docker build --platform linux/amd64 -t cert-manager-webhook-autodns .
```

## License

MIT - see [LICENSE](LICENSE).

Based on [derJD/cert-manager-webhook-autodns](https://github.com/derJD/cert-manager-webhook-autodns) (Apache-2.0).
