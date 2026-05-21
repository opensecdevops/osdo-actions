# Listas de Verificación de Certificación OSDO

Este documento proporciona listas de verificación para lograr el cumplimiento con los principales estándares de seguridad usando OSDO.

---

## Cumplimiento OWASP Top 10 2021

| Control | Cobertura OSDO | Acción Requerida |
|---------|---------------|-----------------|
| **A01: Control de Acceso Roto** | ✅ osdo-sast (Semgrep) | Habilitar en pipeline |
| **A02: Fallas Criptográficas** | ✅ osdo-secrets-scan + osdo-sast | Habilitar ambos |
| **A03: Inyección** | ✅ osdo-sast (SQL/NoSQL/Command) | Habilitar reglas Semgrep |
| **A04: Diseño Inseguro** | ⚠️ Manual + osdo-sast | Agregar modelado de amenazas |
| **A05: Mala Configuración de Seguridad** | ✅ osdo-iac-scan + osdo-container-scan | Habilitar Checkov/Trivy |
| **A06: Componentes Vulnerables** | ✅ osdo-sca (OSV, Grype) | Habilitar escaneo SCA |
| **A07: Fallas de Autenticación** | ✅ osdo-sast + osdo-dast | Habilitar ambos |
| **A08: Fallas de Integridad de Datos** | ✅ osdo-sbom + osdo-slsa-provenance | Habilitar SBOM + SLSA |
| **A09: Registro de Seguridad** | ⚠️ Responsabilidad de la aplicación | Implementar en la app |
| **A10: SSRF** | ✅ osdo-sast (Reglas SSRF Semgrep) | Habilitar Semgrep |

### Workflow Mínimo para Cumplimiento OWASP

```yaml
jobs:
  owasp-compliance:
    steps:
      - uses: opensecdevops/osdo-actions/osdo-sast@v2      # A01, A03, A07, A10
      - uses: opensecdevops/osdo-actions/osdo-sca@v2       # A06
      - uses: opensecdevops/osdo-actions/osdo-secrets-scan@v2  # A02
      - uses: opensecdevops/osdo-actions/osdo-iac-scan@v2  # A05
      - uses: opensecdevops/osdo-actions/osdo-sbom@v2      # A08
```

---

## SLSA (Niveles de Cadena de Suministro para Artefactos de Software)

### Requisitos SLSA Nivel 1

| Requisito | Cobertura OSDO | Estado |
|-----------|---------------|--------|
| Proceso de compilación documentado | ✅ Workflow de GitHub Actions | Automático |
| Procedencia disponible | ✅ osdo-slsa-provenance | Habilitar |

### Requisitos SLSA Nivel 2

| Requisito | Cobertura OSDO | Estado |
|-----------|---------------|--------|
| Control de versiones utilizado | ✅ Git | Automático |
| Servicio de compilación alojado | ✅ GitHub Actions | Automático |
| Procedencia autenticada | ✅ osdo-slsa-provenance | Habilitar |

### Requisitos SLSA Nivel 3

| Requisito | Cobertura OSDO | Estado |
|-----------|---------------|--------|
| Procedencia no falsificable | ✅ osdo-slsa-provenance (Sigstore) | Habilitar |
| Entorno de compilación aislado | ✅ Runners de GitHub Actions | Automático |
| Artefactos firmados | ✅ osdo-slsa-provenance (Cosign) | Habilitar |

### Workflow para SLSA Nivel 3

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # OIDC para Sigstore
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: make build
      - uses: opensecdevops/osdo-actions/osdo-slsa-provenance@v2
        with:
          subject-path: dist/*
          slsa-level: "3"
          sign-artifacts: true
          upload-to-rekor: true
```

---

## OpenSSF Scorecard

| Verificación | Cobertura OSDO | Cómo Habilitar |
|--------------|---------------|----------------|
| Code-Review | Revisión de PR en GitHub | Configurar protección de ramas |
| Branch-Protection | Configuración de GitHub | Habilitar en ajustes del repositorio |
| Dependency-Update-Tool | Dependabot | Agregar `.github/dependabot.yml` |
| Fuzzing | ✅ osdo-fuzz | Habilitar action de fuzzing |
| SAST | ✅ osdo-sast | Habilitar en pipeline |
| Security-Policy | SECURITY.md | `osdo init` lo crea |
| Signed-Releases | ✅ osdo-slsa-provenance | Habilitar para releases |
| Token-Permissions | Permisos del workflow | Usar permisos mínimos |
| Vulnerabilities | ✅ osdo-sca | Habilitar escaneo SCA |
| License | Archivo LICENSE | Agregar archivo de licencia |

### Configuración Lista para Scorecard

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

```yaml
# Workflow con permisos mínimos
permissions:
  contents: read
  security-events: write
```

---

## Insignia OpenSSF Best Practices

Requisitos para el nivel **Passing**:

| Criterio | Cobertura OSDO |
|----------|---------------|
| Licencia FLOSS | Agregar archivo LICENSE |
| Documentación | osdo init crea el README |
| Compilación funciona | CI/CD en workflow |
| Suite de pruebas automatizada | Agregar pruebas |
| Política de seguridad | SECURITY.md vía osdo init |
| Análisis estático | osdo-sast |
| Corregir vulnerabilidades críticas rápidamente | osdo-sca + alertas |

### Solicitar la Insignia

1. Visitar [bestpractices.coreinfrastructure.org](https://bestpractices.coreinfrastructure.org)
2. Agregar tu proyecto
3. Responder el cuestionario (OSDO proporciona evidencia para la mayoría)

---

## OWASP Mobile Top 10 (2024)

| Control | Cobertura OSDO | Acción Requerida |
|---------|---------------|-----------------|
| **M1: Uso Indebido de Credenciales** | ✅ osdo-mobile-scan | Habilitar verificación de secretos |
| **M2: Cadena de Suministro Inadecuada** | ✅ osdo-sca | Habilitar escaneo de dependencias |
| **M3: Autenticación/Autorización Insegura** | ✅ osdo-mobile-scan | Habilitar patrones de autenticación |
| **M4: Validación de E/S Insuficiente** | ✅ osdo-sast | Habilitar reglas móviles |
| **M5: Comunicación Insegura** | ✅ osdo-mobile-scan | Verificación de SSL pinning |
| **M6: Controles de Privacidad Inadecuados** | ⚠️ Revisión manual | Verificar permisos |
| **M7: Protección Binaria Insuficiente** | ✅ osdo-mobile-scan | Verificación de ofuscación |
| **M8: Mala Configuración de Seguridad** | ✅ osdo-mobile-scan | Análisis de manifest |
| **M9: Almacenamiento de Datos Inseguro** | ✅ osdo-mobile-scan | Patrones de almacenamiento |
| **M10: Criptografía Insuficiente** | ✅ osdo-sast | Reglas de criptografía |

### Workflow de Seguridad Móvil

```yaml
jobs:
  mobile-security:
    steps:
      - uses: opensecdevops/osdo-actions/osdo-mobile-scan@v2
        with:
          app-path: "./app.apk"
          platform: "android"
          check-ssl-pinning: true
          check-obfuscation: true
```

---

## OWASP Smart Contract Top 10 (2023)

| Control | Cobertura OSDO | Acción Requerida |
|---------|---------------|-----------------|
| **SC01: Reentrancy** | ✅ osdo-smart-contract-audit | Habilitar Slither |
| **SC02: Control de Acceso** | ✅ osdo-smart-contract-audit | Detección de patrones |
| **SC03: Problemas Aritméticos** | ✅ osdo-smart-contract-audit | Solidity 0.8+ |
| **SC04: Retorno Sin Verificar** | ✅ osdo-smart-contract-audit | Verificación Slither |
| **SC05: Denegación de Servicio** | ✅ osdo-smart-contract-audit | Análisis de bucles |
| **SC06: Aleatoriedad Incorrecta** | ✅ osdo-smart-contract-audit | Detección de fuentes |
| **SC07: Front-Running** | ⚠️ Revisión de diseño | Análisis manual |
| **SC08: Dependencia de Timestamp** | ✅ osdo-smart-contract-audit | Detección de uso |
| **SC09: Direcciones Cortas** | ✅ osdo-smart-contract-audit | Validación de entrada |
| **SC10: Desconocidos** | ⚠️ Mythril | Ejecución simbólica |

### Workflow de Smart Contract

```yaml
jobs:
  web3-security:
    steps:
      - uses: opensecdevops/osdo-actions/osdo-smart-contract-audit@v2
        with:
          contracts-path: "./contracts"
          scanners: "slither,mythril"
          check-reentrancy: true
```

---

## OWASP GenAI Security Top 10 (2025)

| Control | Cobertura OSDO | Acción Requerida |
|---------|---------------|-----------------|
| **LLM01: Inyección de Prompts** | ✅ osdo-llm-scan | Habilitar verificaciones de prompts |
| **LLM02: Salida Insegura** | ✅ osdo-llm-scan | Manejo de salida |
| **LLM03: Envenenamiento de Entrenamiento** | ⚠️ Manual | Validación de datos |
| **LLM04: DoS de Modelo** | ⚠️ Manual | Limitación de tasa |
| **LLM05: Cadena de Suministro** | ✅ osdo-llm-scan | Serialización de modelos |
| **LLM06: Divulgación de Información Sensible** | ✅ osdo-llm-scan | Verificación de exposición PII |
| **LLM07: Plugin Inseguro** | ⚠️ osdo-sast | Revisión de funciones |
| **LLM08: Agencia Excesiva** | ✅ osdo-llm-scan | Análisis de permisos |
| **LLM09: Sobredependencia** | ⚠️ Manual | Revisión humana |
| **LLM10: Robo de Modelo** | ⚠️ Manual | Control de acceso |

### Workflow de Seguridad LLM

```yaml
jobs:
  llm-security:
    steps:
      - uses: opensecdevops/osdo-actions/osdo-llm-scan@v2
        with:
          source-path: "."
          check-prompt-injection: true
          check-pii-exposure: true
```

---

## Requisitos CNCF

Para proyectos CNCF Sandbox/Incubating:

| Requisito | Cobertura OSDO |
|-----------|---------------|
| Adopta el Código de Conducta CNCF | Agregar a CONTRIBUTING.md |
| Usa licencia aprobada por OSI | Agregar LICENSE |
| Proceso de divulgación de seguridad | SECURITY.md |
| Escaneo de dependencias | osdo-sca |
| Escaneo de contenedores | osdo-container-scan |
| Generación de SBOM | osdo-sbom |

---

## SOC 2 Tipo II (Controles de Desarrollo)

| Control | Cobertura OSDO |
|---------|---------------|
| CC6.1 Acceso lógico | Protección de ramas + revisiones de PR |
| CC6.6 Límites del sistema | Escaneo de contenedores |
| CC6.7 Transmisión de datos | Verificaciones TLS vía osdo-dast |
| CC7.1 Detectar vulnerabilidades | osdo-sast + osdo-sca |
| CC7.2 Monitorear incidentes | osdo-secrets-scan |
| CC8.1 Gestión de cambios | Workflow de Git + PR |

---

## Comandos Rápidos

```bash
# Verificar cumplimiento OWASP
osdo certify --standard owasp

# Verificar nivel SLSA
osdo certify --standard slsa

# Verificar preparación OpenSSF
osdo certify --standard openssf

# Generar informe completo
osdo certify --standard owasp --report
```

---

## Ver También

- [Referencia de Actions OSDO](ACTIONS_REFERENCE.md)
- [De 0 a OSDO en 1 Hora](QUICKSTART.md)
- [Guía de Política como Código](POLICY_GATE.md)
