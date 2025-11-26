# IntegrityGate GitHub Action

Verify code integrity with cryptographic signatures, Merkle tree validation, and OPA policy compliance. Part of the EpochCore Quantum ecosystem.

## Features

- **Merkle Tree Validation** - Compute and verify file integrity using Merkle trees
- **Signature Verification** - Verify cryptographic signatures on commits and files
- **OPA Policy Compliance** - Check against Open Policy Agent rules
- **Deep Analysis (Pro)** - AI-powered security scanning with license key

## Usage

```yaml
name: Integrity Check
on: [push, pull_request]

jobs:
  integrity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run IntegrityGate
        uses: epochcoreqcs/integrity-gate-action@v1
        with:
          mode: 'standard'
          signature-verify: 'true'
          merkle-validate: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `mode` | Verification mode: quick, standard, or deep | `standard` |
| `policy-path` | Path to OPA policy files | `.epochcore/policies` |
| `signature-verify` | Enable signature verification | `true` |
| `merkle-validate` | Enable Merkle tree validation | `true` |
| `fail-on-warning` | Fail on warnings | `false` |
| `license-key` | EpochCore license for Pro features | `` |
| `worker-endpoint` | Custom worker endpoint | `https://epochcore-unified-worker.epochcoreras.workers.dev` |

## Outputs

| Output | Description |
|--------|-------------|
| `integrity-score` | Overall integrity score (0-100) |
| `signature-status` | Signature verification result |
| `merkle-root` | Computed Merkle root hash |
| `policy-violations` | Number of policy violations |
| `report-url` | URL to detailed report |

## Pricing

- **Free** - Basic integrity checks, 100 runs/month
- **Starter ($29/mo)** - Unlimited runs, standard mode
- **Professional ($97/mo)** - Deep analysis, custom policies
- **Vanguard ($497/mo)** - White-label, team features, priority support

## License

MIT - EpochCore Quantum Enterprise
