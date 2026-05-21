# Referencia de OSDO Actions

Referencia completa de todas las OSDO GitHub Actions.

---

## Actions de Escaneo de Seguridad

### osdo-sast

**Pruebas de Seguridad de Aplicaciones Estáticas**

```yaml
- uses: opensecdevops/osdo-actions/osdo-sast@v2
  with:
    path: "."                    # Path to scan
    scanners: "semgrep,bandit,eslint"  # Scanners to use
    fail-on-finding: "true"      # Fail if findings
    severity-threshold: "ERROR"  # Minimum severity to fail
    output-format: "sarif"       # Output format
```

| Escáner | Lenguajes | Propósito |
|---------|-----------|---------|
| Semgrep | Multilenguaje | Reglas de seguridad + patrones personalizados |
| Bandit | Python | Seguridad específica de Python |
| ESLint + security | JavaScript/TypeScript | Linting de seguridad |

---

### osdo-sca

**Análisis de Composición de Software**

```yaml
- uses: opensecdevops/osdo-actions/osdo-sca@v2
  with:
    path: "."
    scanners: "osv,grype"        # osv, grype, npm, pip, go
    fail-on-critical: "true"     # Fail on CRITICAL vulns
    ignore-unfixed: "false"      # Include unfixed vulns
```

| Escáner | Gestores de Paquetes |
|---------|-----------------|
| OSV-Scanner | Todos (npm, pip, go, maven, cargo, etc.) |
| Grype | Imágenes de contenedor + sistemas de archivos |
| npm audit | package.json |
| pip-audit | requirements.txt |
| govulncheck | go.mod |

---

### osdo-secrets-scan

**Detección de Secretos y Credenciales**

```yaml
- uses: opensecdevops/osdo-actions/osdo-secrets-scan@v2
  with:
    scanners: "gitleaks,trufflehog,detect-secrets"
    scan-mode: "all-history"     # all-history, staged, directory
    fail-on-finding: "true"
    baseline-file: ".secrets-baseline"
```

| Escáner | Característica |
|---------|---------|
| Gitleaks | Historial de Git, salida SARIF |
| TruffleHog | Detección de entropía, secretos verificados |
| detect-secrets | Soporte de línea base, lista de permitidos |

---

### osdo-container-scan

**Seguridad de Contenedores**

```yaml
- uses: opensecdevops/osdo-actions/osdo-container-scan@v2
  with:
    image: "myapp:latest"
    scanners: "trivy,grype,hadolint"
    fail-on: "HIGH"              # CRITICAL, HIGH, MEDIUM, LOW
    include-sbom: "true"
```

| Escáner | Propósito |
|---------|---------|
| Trivy | Vulnerabilidades, configuraciones incorrectas |
| Grype | Escaneo basado en SBOM |
| Hadolint | Linting de Dockerfile |

---

### osdo-iac-scan

**Seguridad de Infraestructura como Código**

```yaml
- uses: opensecdevops/osdo-actions/osdo-iac-scan@v2
  with:
    path: "./deploy"
    scanners: "checkov,kics,tfsec"
    framework: "terraform"       # terraform, kubernetes, cloudformation
    fail-on-high: "true"
```

| Escáner | Tipos de IaC |
|---------|-----------|
| Checkov | Terraform, K8s, CloudFormation, ARM |
| KICS | 40+ plataformas |
| tfsec | Específico de Terraform |

---

### osdo-dast-scan

**Pruebas de Seguridad de Aplicaciones Dinámicas**

```yaml
- uses: opensecdevops/osdo-actions/osdo-dast-scan@v2
  with:
    target: "https://staging.example.com"
    scan-type: "baseline"        # baseline, full, api
    zap-rules-file: ".zap/rules.tsv"
```

---

## Actions de Cadena de Suministro

### osdo-sbom

**Lista de Materiales de Software**

```yaml
- uses: opensecdevops/osdo-actions/osdo-sbom@v2
  with:
    path: "."
    format: "both"               # spdx, cyclonedx, both
    output-prefix: "sbom"
    upload-artifact: "true"
    validate-schema: "true"
```

**Salidas**: SPDX 2.3 JSON + CycloneDX 1.5 JSON

---

### osdo-slsa-provenance

**Cumplimiento SLSA Nivel 3**

```yaml
- uses: opensecdevops/osdo-actions/osdo-slsa-provenance@v2
  with:
    subject-path: "dist/*"
    slsa-level: "3"
    sign-artifacts: "true"
    upload-to-rekor: "true"
```

| Característica | Descripción |
|---------|-------------|
| Sigstore/Cosign | Firma sin clave |
| Rekor | Registro de transparencia |
| GitHub Attestations | API de atestación nativa |

---

### osdo-policy-gate

**Política como Código**

```yaml
- uses: opensecdevops/osdo-actions/osdo-policy-gate@v2
  with:
    engine: "opa"                # opa, kyverno
    policy-paths: ".osdo/policies"
    builtin-policies: "security,compliance"
    target-resources: "deploy/**/*.yaml"
    fail-on-violation: "true"
```

**Políticas Integradas**:
- `security`: Sin root, límites de recursos, root de solo lectura
- `compliance`: Etiquetas requeridas, sondas de estado
- `terraform`: Cifrado S3, grupos de seguridad

---

### osdo-fuzz

**Pruebas de Fuzzing**

```yaml
- uses: opensecdevops/osdo-actions/osdo-fuzz@v2
  with:
    target-path: "."
    language: "auto"             # go, python, rust, javascript, c
    fuzz-time: "300"             # Seconds
    sanitizers: "address"
    fail-on-crash: "true"
```

| Lenguaje | Fuzzer |
|----------|--------|
| Go | Nativo `go test -fuzz` |
| Python | Atheris |
| Rust | cargo-fuzz |
| JavaScript | jsfuzz |
| C/C++ | AFL++ |

---

## Actions de Utilidad

### osdo-quality-gate

**Aplicación de Calidad**

```yaml
- uses: opensecdevops/osdo-actions/osdo-quality-gate@v2
  with:
    coverage-threshold: "80"
    max-critical: "0"
    max-high: "5"
```

---

### osdo-compliance-report

**Informes Consolidados**

```yaml
- uses: opensecdevops/osdo-actions/osdo-compliance-report@v2
  with:
    results-dir: ".osdo/results"
    output-format: "markdown"
```

---

## Patrones Comunes

### Pipeline de Seguridad Completo

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-sast@v2
      - uses: opensecdevops/osdo-actions/osdo-sca@v2
      - uses: opensecdevops/osdo-actions/osdo-secrets-scan@v2
      - uses: opensecdevops/osdo-actions/osdo-sbom@v2
```

### Contenedor + Compuerta de Política

```yaml
jobs:
  container:
    steps:
      - uses: opensecdevops/osdo-actions/osdo-container-scan@v2
        with:
          image: ${{ env.IMAGE }}
      - uses: opensecdevops/osdo-actions/osdo-policy-gate@v2
        with:
          target-resources: "deploy/*.yaml"
```

### Publicación con SLSA

```yaml
jobs:
  release:
    if: github.event_name == 'release'
    steps:
      - uses: opensecdevops/osdo-actions/osdo-sbom@v2
      - uses: opensecdevops/osdo-actions/osdo-slsa-provenance@v2
        with:
          slsa-level: "3"
```

---

## Actions de Seguridad Especializadas

### osdo-smart-contract-audit

**Seguridad de Contratos Inteligentes (Web3)**

```yaml
- uses: opensecdevops/osdo-actions/osdo-smart-contract-audit@v2
  with:
    contracts-path: "./contracts"
    scanners: "slither,mythril,solhint"
    solidity-version: "0.8.20"
    fail-on-severity: "HIGH"
    check-reentrancy: true
    check-gas-optimization: true
```

| Escáner | Propósito |
|---------|---------|
| Slither | Análisis estático rápido |
| Mythril | Ejecución simbólica |
| Solhint | Linting de Solidity |

**Cobertura del OWASP Smart Contract Top 10**: SC01 (Reentrada), SC02 (Control de Acceso), SC03 (Aritmética), SC05 (DoS), SC06 (Aleatoriedad)

---

### osdo-llm-scan

**Seguridad de LLM/GenAI**

```yaml
- uses: opensecdevops/osdo-actions/osdo-llm-scan@v2
  with:
    source-path: "."
    check-prompt-injection: true
    check-pii-exposure: true
    check-model-serialization: true
    check-output-handling: true
```

| Verificación | OWASP GenAI |
|-------|-------------|
| Prompt Injection | LLM01 |
| Insecure Output | LLM02 |
| Model Serialization | LLM05 |
| PII Exposure | LLM06 |

---

## Referencia de Salidas

Todas las actions producen salidas en `.osdo/results/<action>/`:

| Action | Archivos de Salida |
|--------|--------------|
| osdo-sast | `semgrep.sarif`, `bandit.json` |
| osdo-sca | `osv.json`, `grype.json` |
| osdo-secrets-scan | `gitleaks.sarif`, `trufflehog.json` |
| osdo-sbom | `sbom-spdx.json`, `sbom-cyclonedx.json` |
| osdo-container-scan | `trivy.sarif`, `hadolint.json` |
| osdo-slsa-provenance | `provenance.intoto.jsonl` |

---

## Permisos

Permisos mínimos para la mayoría de las actions:

```yaml
permissions:
  contents: read
  security-events: write  # For SARIF upload
```

Para SLSA provenance:

```yaml
permissions:
  contents: read
  id-token: write         # OIDC for Sigstore
  packages: write         # If pushing to registry
```
