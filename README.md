# OSDO Actions

**Open SecDevOps (OSDO) - Actions Repository**

Monorepo centralizado que mantiene todas las **GitHub Actions granulares** para el framework OSDO. Cada acción es **independiente, versionada y reutilizable**.

---

## 📚 Tabla de Contenidos

- [Descripción](#descripción)
- [Estructura](#estructura)
- [Acciones Disponibles](#acciones-disponibles)
- [Uso Rápido](#uso-rápido)
- [Versionado](#versionado)
- [Relación con Otros Repos](#relación-con-otros-repos)
- [Contribución](#contribución)
- [Soporte](#soporte)

---

## Descripción

`osdo-actions` es un **monorepo** que alberga todas las GitHub Actions utilizadas por el framework OSDO. Proporciona:

**Acciones Granulares** - Cada herramienta de seguridad en una acción independiente  
**Versionado Semántico** - Control de versiones independiente por acción  
**Reutilización** - Úsalas en tus propios workflows  
**Publicación Centralizada** - Un único workflow para publicar todas  
**Documentación Completa** - Cada acción bien documentada  

---

## Estructura

```
osdo-actions/
├── actions/
│   ├── osdo-sca/                    # Software Composition Analysis
│   │   └── action.yml               # npm audit, Safety, etc.
│   ├── osdo-sast/                   # Static Application Security Testing
│   │   └── action.yml               # Semgrep, Bandit, etc.
│   ├── osdo-secrets-scan/           # Detección de secretos
│   │   └── action.yml               # TruffleHog, Gitleaks
│   ├── osdo-container-scan/         # Container security
│   │   └── action.yml               # Trivy, Hadolint
│   ├── osdo-iac-scan/               # Infrastructure as Code scanning
│   │   └── action.yml               # Checkov, TFLint, etc.
│   ├── osdo-sbom/                   # Software Bill of Materials
│   │   └── action.yml               # CycloneDX, generación
│   ├── osdo-sign/                   # Code signing & attestation
│   │   └── action.yml               # cosign, attestation
│   ├── osdo-test-quality/           # Test & quality checks
│   │   └── action.yml               # Coverage, quality gates
│   └── osdo-compliance-report/      # Compliance reporting
│       └── action.yml               # Reporte de compliance
├── .github/
│   └── workflows/
│       └── publish.yml              # Publicar releases
├── docs/                            # Documentación específica
├── README.md                        # Este archivo
├── CHANGELOG.md                     # Historial de versiones
└── LICENSE
```

---

## Acciones Disponibles

| Acción | Propósito | Versión | Use |
|--------|-----------|---------|-----|
| **osdo-sca** | Análisis de composición de software | v1.0.0+ | npm, pip, maven, etc. |
| **osdo-sast** | Análisis estático de código | v1.0.0+ | Semgrep, Bandit, etc. |
| **osdo-secrets-scan** | Detección de secretos | v1.0.0+ | TruffleHog, Gitleaks |
| **osdo-container-scan** | Escaneo de contenedores | v1.0.0+ | Trivy, Grype, Hadolint, SBOM |
| **osdo-iac-scan** | Infrastructure as Code | v1.0.0+ | Checkov, KICS, tfsec, Terrascan |
| **osdo-sbom** | Bill of Materials | v1.0.0+ | CycloneDX, SPDX |
| **osdo-sign** | Code signing | v1.0.0+ | cosign, attestation |
| **osdo-test-quality** | Tests & quality | v1.0.0+ | Coverage, gates |
| **osdo-compliance-report** | Compliance report | v1.0.0+ | Consolidación de reportes |
| **osdo-dast-scan** | Dynamic App Security Testing | v1.0.0+ | OWASP ZAP, SSL/TLS checks |
| **osdo-api-scan** | API Security Testing | v1.0.0+ | OpenAPI validation, fuzzing |
| **osdo-mobile-scan** | Mobile Security | v1.0.0+ | MASVS compliance, iOS/Android |
| **osdo-cloud-scan** | Cloud Security | v1.0.0+ | AWS/Azure/GCP, Prowler |
| **osdo-license-scan** | License Compliance | v1.0.0+ | License detection, policy enforcement |

---

## Uso Rápido

### Usar una Acción Individual

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
      
      # Usar acción directamente
      - name: SCA Scan
        uses: opensecdevops/osdo-actions/actions/osdo-sca@osdo-sca/v1.0.0
        with:
          results-dir: '.osdo/results'
          enable-npm: true
          enable-python: true
```

### Combinar Múltiples Acciones

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

## Versionado

Cada acción sigue **Semantic Versioning** con tags independientes:

```
osdo-<action-name>/v<MAJOR>.<MINOR>.<PATCH>
```

**Ejemplos:**
```
osdo-sca/v1.0.0              # Primera versión
osdo-sca/v1.1.0              # Nueva feature (backwards compatible)
osdo-sast/v2.0.0             # Breaking change
```

### Publicar Nueva Versión

```bash
# 1. Hacer cambios a la acción
git checkout -b feature/mejora-sca

# 2. Editar acción
# actions/osdo-sca/action.yml

# 3. Commit y Push
git add .
git commit -m "feat(osdo-sca): agregar soporte para npm semver ranges"
git push origin feature/mejora-sca

# 4. Crear PR y obtener aprobación

# 5. Mergear a main

# 6. Publicar release
gh release create osdo-sca/v1.1.0 \
  --title "Release: osdo-sca v1.1.0" \
  --notes "Soporte para npm semver ranges"
```

---

## Relación con Otros Repos

### Arquitectura de Tres Capas

```
┌──────────────────────────────────────────────────┐
│     osdo-workflow-template (Orquestador)         │
│  Usa acciones de osdo-actions + osdo-workflows   │
└────────────────────┬─────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼────────────┐    ┌─────▼──────────────┐
    │  osdo-actions   │    │  osdo-workflows    │
    │  (Granulares)   │    │  (Reutilizables)   │
    └─────────────────┘    └────────────────────┘
```

### **osdo-actions** (Este Repositorio)
- Acciones **granulares** e **independientes**
- Cada herramienta = 1 acción
- Reutilizables en cualquier contexto
- Versionadas individualmente

**Úsalas cuando:**
- Necesites **control granular**
- Quieras combinar herramientas **específicas**
- Desarrolles tus **propias orquestaciones**

---

### **osdo-workflow-template**
- 🎯 Framework **completo** y **opinado**
- 🔗 Orquestra acciones de `osdo-actions`
- 📦 Proporciona workflows reutilizables
- ⚙️ Best practices preconfiguradas

**Úsalas cuando:**
- Quieras un pipeline **completo**
- No necesites **customización extrema**
- Busques **"security by default"**

---

### **osdo-workflows**
- 📋 Workflows reutilizables
- 🎯 Para scenarios específicos
- 🔄 Complementarios al framework

---

## 🤝 Cómo Contribuir

### 1️⃣ Reportar Issues

Encuentra un bug o tienes una idea? Abre un [GitHub Issue](https://github.com/opensecdevops/osdo-actions/issues):

```
Título: [BUG] osdo-sca no detecta vulnerabilidades en Node.js v18

Descripción:
- Qué pasó: ...
- Qué esperabas: ...
- Cómo reproducirlo: ...
- Versión: osdo-sca/v1.0.0
```

### 2️⃣ Contribuir Código

```bash
# 1. Fork y clonar
git clone https://github.com/tu-usuario/osdo-actions.git
cd osdo-actions

# 2. Crear rama
git checkout -b feature/nueva-herramienta

# 3. Desarrollar nueva acción
mkdir -p actions/osdo-tu-accion
# Crear action.yml, entrypoint.sh, README.md

# 4. Escribir tests
# tests/osdo-tu-accion/

# 5. Documentar
# actions/osdo-tu-accion/README.md

# 6. Commit y push
git add .
git commit -m "feat(osdo-tu-accion): descripción clara"
git push origin feature/nueva-herramienta

# 7. Abrir Pull Request
```

### 3️⃣ Estructura de Nueva Acción

```yaml
# actions/osdo-tu-accion/action.yml
name: 'OSDO - Tu Acción'
description: 'Descripción clara y concisa'
author: 'OpenSecDevOps'

inputs:
  results-dir:
    description: 'Directorio de resultados'
    required: false
    default: '.osdo/results'
  
  enable-feature:
    description: 'Habilitar feature X'
    required: false
    default: 'true'

outputs:
  vulnerabilities-found:
    description: 'Total de vulnerabilidades'
    value: ${{ steps.scan.outputs.vulnerabilities-found }}

runs:
  using: 'docker'
  image: 'docker://ubuntu:22.04'
  entrypoint: 'entrypoint.sh'
```

### 4️⃣ Guidelines

✅ **DO:**
- Documentar inputs/outputs
- Incluir ejemplos de uso
- Seguir convenciones (naming, estructura)
- Versionar según semver
- Escribir tests

❌ **DON'T:**
- Mezclar responsabilidades
- Hardcodear valores
- Omitir documentación
- Breaking changes sin major version bump

---

## 📚 Documentación

- 📖 [ARCHITECTURE.md](../ARCHITECTURE.md) - Cómo todo encaja
- 📋 [INTEGRATION_GUIDE.md](../INTEGRATION_GUIDE.md) - Integración completa
- 🤝 [CONTRIBUTING.md](../CONTRIBUTING.md) - Guía detallada de contribución
- 🔧 [docs/ACTIONS_REFERENCE.md](docs/ACTIONS_REFERENCE.md) - Referencia técnica

---

## 🆘 Soporte

### Encuentra Ayuda

- 📖 [Ejemplos Completos](docs/examples.md)
- 🐛 [Troubleshooting](docs/TROUBLESHOOTING.md)
- 💬 [GitHub Discussions](https://github.com/opensecdevops/osdo-actions/discussions)
- 🐙 [GitHub Issues](https://github.com/opensecdevops/osdo-actions/issues)

### Reportar Seguridad

Para vulnerabilidades de seguridad, **NO** abras un issue público. En su lugar, usa:
[GitHub Security Advisory](https://github.com/opensecdevops/osdo-actions/security/advisories)

---

## 📊 Impacto

- **14 Actions** en producción
- **30+ Security Tools** integradas
- **10+ Lenguajes** soportados
- **100+ Proyectos** dependientes

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

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE)

---

## 🌟 ¿Te Gusta? Dale una Estrella ⭐

Si encuentras útil este proyecto, por favor dale una estrella en [GitHub](https://github.com/opensecdevops/osdo-actions). Ayuda a otros a descubrirlo!

---

**OSDO Actions** - Seguridad modular, escalable y reutilizable.

Made with ❤️ by the OpenSecDevOps Community  
[Website](https://opensecdevops.dev) | [Twitter](https://twitter.com/opensecdevops) | [Slack](https://opensecdevops.slack.com)
