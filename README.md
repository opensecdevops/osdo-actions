English | [Español](README.es.md)

# OSDO Actions

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/opensecdevops/osdo-actions/badge)](https://securityscorecards.dev/viewer/?uri=github.com/opensecdevops/osdo-actions)

**Open SecDevOps (OSDO) - Actions Repository**

Centralized monorepo that maintains all the **granular GitHub Actions** for the OSDO framework. Each action is **independent, versioned and reusable**.

---

## 📚 Table of Contents

- [Description](#description)
- [Structure](#structure)
- [Available Actions](#available-actions)
- [Quick Start](#quick-start)
- [Versioning](#versioning)
- [Relationship with Other Repos](#relationship-with-other-repos)
- [Contributing](#contributing)
- [Support](#support)

---

## Description

`osdo-actions` is a **monorepo** that hosts all the GitHub Actions used by the OSDO framework. It provides:

**Granular Actions** - Each security tool in its own independent action
**Semantic Versioning** - Independent versioning per action
**Reusability** - Use them in your own workflows
**Centralized Publishing** - A single workflow to publish all of them
**Complete Documentation** - Every action is well documented

---

## Structure

```
osdo-actions/
├── actions/
│   ├── osdo-sca/                    # Software Composition Analysis
│   │   └── action.yml               # npm audit, Safety, etc.
│   ├── osdo-sast/                   # Static Application Security Testing
│   │   └── action.yml               # Semgrep, Bandit, etc.
│   ├── osdo-secrets-scan/           # Secret detection
│   │   └── action.yml               # TruffleHog, Gitleaks
│   ├── osdo-container-scan/         # Container security
│   │   └── action.yml               # Trivy, Hadolint
│   ├── osdo-iac-scan/               # Infrastructure as Code scanning
│   │   └── action.yml               # Checkov, TFLint, etc.
│   ├── osdo-sbom/                   # Software Bill of Materials
│   │   └── action.yml               # CycloneDX, generation
│   ├── osdo-sign/                   # Code signing & attestation
│   │   └── action.yml               # cosign, attestation
│   ├── osdo-test-quality/           # Test & quality checks
│   │   └── action.yml               # Coverage, quality gates
│   └── osdo-compliance-report/      # Compliance reporting
│       └── action.yml               # Compliance report
├── .github/
│   └── workflows/
│       └── publish.yml              # Publish releases
├── docs/                            # Specific documentation
├── README.md                        # This file
├── CHANGELOG.md                     # Version history
└── LICENSE
```

---

## Available Actions

| Action | Purpose | Version | Used for |
|--------|---------|---------|----------|
| **osdo-sca** | Software composition analysis | v1.0.0+ | npm, pip, maven, etc. |
| **osdo-sast** | Static code analysis | v1.0.0+ | Semgrep, Bandit, etc. |
| **osdo-secrets-scan** | Secret detection | v1.0.0+ | TruffleHog, Gitleaks |
| **osdo-container-scan** | Container scanning | v1.0.0+ | Trivy, Grype, Hadolint, SBOM |
| **osdo-iac-scan** | Infrastructure as Code | v1.0.0+ | Checkov, KICS, tfsec, Terrascan |
| **osdo-sbom** | Bill of Materials | v1.0.0+ | CycloneDX, SPDX |
| **osdo-sign** | Code signing | v1.0.0+ | cosign, attestation |
| **osdo-test-quality** | Tests & quality | v1.0.0+ | Coverage, gates |
| **osdo-compliance-report** | Compliance report | v1.0.0+ | Report consolidation |
| **osdo-dast-scan** | Dynamic Application Security Testing | v1.0.0+ | OWASP ZAP, SSL/TLS checks |
| **osdo-api-scan** | API security testing | v1.0.0+ | OpenAPI validation, fuzzing |
| **osdo-mobile-scan** | Mobile security | v1.0.0+ | MASVS compliance, iOS/Android |
| **osdo-cloud-scan** | Cloud security | v1.0.0+ | AWS/Azure/GCP, Prowler |
| **osdo-license-scan** | License compliance | v1.0.0+ | License detection, policy enforcement |
| **osdo-llm-scan** | LLM/AI security | v1.0.0+ | Prompt injection, model security |
| **osdo-build-security** | Secure build with SBOM | v1.0.0+ | Build hardening, SBOM generation |
| **osdo-fuzz** | Application fuzzing | v1.0.0+ | Go, Python Atheris, Rust cargo-fuzz, JS jsfuzz, C/C++ AFL++ |
| **osdo-policy-gate** | Policy as Code | v1.0.0+ | OPA, Kyverno |
| **osdo-security-gate** | Security quality gate | v1.0.0+ | Severity thresholds, pipeline blocking |
| **osdo-setup-env** | Environment setup | v1.0.0+ | Tool setup and environment variables |
| **osdo-slsa-provenance** | SLSA Provenance | v1.0.0+ | SLSA Level 3, Sigstore/Cosign, Rekor |
| **osdo-smart-contract-audit** | Smart contract auditing | v1.0.0+ | Slither, Mythril, Solhint for Solidity |

---

## Quick Start

### Use a Single Action

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      # Use the action directly
      - name: SCA Scan
        uses: opensecdevops/osdo-actions/actions/osdo-sca@osdo-sca/v1.0.0
        with:
          results-dir: '.osdo/results'
          enable-npm: true
          enable-python: true
```

### Combine Multiple Actions

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: SCA Analysis
        uses: opensecdevops/osdo-actions/actions/osdo-sca@osdo-sca/v1.0.0
      
      - name: SAST Analysis
        uses: opensecdevops/osdo-actions/actions/osdo-sast@osdo-sast/v1.0.0
      
      - name: Secrets Scan
        uses: opensecdevops/osdo-actions/actions/osdo-secrets-scan@osdo-secrets-scan/v1.0.0
      
      - name: Generate Report
        uses: opensecdevops/osdo-actions/actions/osdo-compliance-report@osdo-compliance-report/v1.0.0
```

---

## Versioning

Each action follows **Semantic Versioning** with independent tags:

```
osdo-<action-name>/v<MAJOR>.<MINOR>.<PATCH>
```

**Examples:**
```
osdo-sca/v1.0.0              # First version
osdo-sca/v1.1.0              # New feature (backwards compatible)
osdo-sast/v2.0.0             # Breaking change
```

### Publish a New Version

```bash
# 1. Make changes to the action
git checkout -b feature/improve-sca

# 2. Edit the action
# actions/osdo-sca/action.yml

# 3. Commit and push
git add .
git commit -m "feat(osdo-sca): add support for npm semver ranges"
git push origin feature/improve-sca

# 4. Open a PR and get approval

# 5. Merge into main

# 6. Publish the release
gh release create osdo-sca/v1.1.0 \
  --title "Release: osdo-sca v1.1.0" \
  --notes "Support for npm semver ranges"
```

---

## Relationship with Other Repos

### Three-Layer Architecture

```
┌──────────────────────────────────────────────────┐
│     osdo-workflow-template (Orchestrator)        │
│  Uses actions from osdo-actions + osdo-workflows │
└────────────────────┬─────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼────────────┐    ┌─────▼──────────────┐
    │  osdo-actions   │    │  osdo-workflows    │
    │  (Granular)     │    │  (Reusable)        │
    └─────────────────┘    └────────────────────┘
```

### **osdo-actions** (This Repository)
- **Granular** and independent actions
- One tool = one action
- Reusable in any context
- Individually versioned

**Use it when:**
- You need **granular control**
- You want to combine **specific** tools
- You are building your **own orchestrations**

---

### **osdo-workflow-template**
- 🎯 **Complete** and **opinionated** framework
- 🔗 Orchestrates actions from `osdo-actions`
- 📦 Provides reusable workflows
- ⚙️ Preconfigured best practices

**Use it when:**
- You want a **complete** pipeline
- You don't need **extreme customization**
- You are looking for **security by default**

---

### **osdo-workflows**
- 📋 Reusable workflows
- 🎯 For specific scenarios
- 🔄 Complementary to the framework

---

## 🤝 How to Contribute

### 1️⃣ Report Issues

Found a bug or have an idea? Open a [GitHub Issue](https://github.com/opensecdevops/osdo-actions/issues):

```
Title: [BUG] osdo-sca does not detect vulnerabilities in Node.js v18

Description:
- What happened: ...
- What you expected: ...
- How to reproduce: ...
- Version: osdo-sca/v1.0.0
```

### 2️⃣ Contribute Code

```bash
# 1. Fork and clone
git clone https://github.com/your-username/osdo-actions.git
cd osdo-actions

# 2. Create a branch
git checkout -b feature/new-tool

# 3. Develop the new action
mkdir -p actions/osdo-your-action
# Create action.yml, entrypoint.sh, README.md

# 4. Write tests
# tests/osdo-your-action/

# 5. Document it
# actions/osdo-your-action/README.md

# 6. Commit and push
git add .
git commit -m "feat(osdo-your-action): clear description"
git push origin feature/new-tool

# 7. Open a Pull Request
```

### 3️⃣ New Action Structure

```yaml
# actions/osdo-your-action/action.yml
name: 'OSDO - Your Action'
description: 'Clear and concise description'
author: 'OpenSecDevOps'

inputs:
  results-dir:
    description: 'Results directory'
    required: false
    default: '.osdo/results'
  
  enable-feature:
    description: 'Enable feature X'
    required: false
    default: 'true'

outputs:
  vulnerabilities-found:
    description: 'Total vulnerabilities'
    value: ${{ steps.scan.outputs.vulnerabilities-found }}

runs:
  using: 'docker'
  image: 'docker://ubuntu:22.04'
  entrypoint: 'entrypoint.sh'
```

### 4️⃣ Guidelines

✅ **DO:**
- Document inputs and outputs
- Include usage examples
- Follow conventions (naming, structure)
- Version according to semver
- Write tests

❌ **DON'T:**
- Mix responsibilities
- Hardcode values
- Skip documentation
- Make breaking changes without a major version bump

---

## 📚 Documentation

- 🔧 [docs/ACTIONS_REFERENCE.md](docs/ACTIONS_REFERENCE.md) - Technical reference
- 🚀 [docs/QUICKSTART.md](docs/QUICKSTART.md) - Quick start
- 🏅 [docs/OPENSSF_BADGE_GUIDE.md](docs/OPENSSF_BADGE_GUIDE.md) - OpenSSF Badge guide
- ✅ [docs/CERTIFICATION_CHECKLISTS.md](docs/CERTIFICATION_CHECKLISTS.md) - Certification checklists

---

## 🆘 Support

### Get Help

- 📖 [Full Examples](docs/QUICKSTART.md)
- 💬 [GitHub Discussions](https://github.com/opensecdevops/osdo-actions/discussions)
- 🐙 [GitHub Issues](https://github.com/opensecdevops/osdo-actions/issues)

### Report Security Issues

For security vulnerabilities, do **NOT** open a public issue. Instead, use:
[GitHub Security Advisory](https://github.com/opensecdevops/osdo-actions/security/advisories)

---

## 📊 Impact

- **22 Actions** in production
- **30+ Security Tools** integrated
- **10+ Languages** supported
- **100+ Dependent Projects**

---

## 🎯 Roadmap

- [x] DAST (Dynamic Application Security Testing)
- [x] License Compliance scanning
- [x] API Security Testing
- [x] Mobile Security (MASVS)
- [x] Cloud Security (Multi-cloud)
- [ ] Real-time security dashboard
- [ ] ML-based anomaly detection
- [ ] Custom rule engine

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 🌟 Like It? Give It a Star ⭐

If you find this project useful, please give it a star on [GitHub](https://github.com/opensecdevops/osdo-actions). It helps others discover it!

---

**OSDO Actions** - Modular, scalable and reusable security.

Made with ❤️ by the OpenSecDevOps Community  
[Website](https://opensecdevops.dev) | [Twitter](https://twitter.com/opensecdevops) | [Slack](https://opensecdevops.slack.com)
