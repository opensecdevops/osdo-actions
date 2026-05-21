# Solicitud de Insignia OpenSSF Best Practices

Esta guía te ayuda a preparar y enviar tu solicitud de Insignia OpenSSF Best Practices.

## Descripción General

La [Insignia OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/) demuestra que tu proyecto sigue las mejores prácticas de seguridad. OSDO te ayuda a cumplir la mayoría de los requisitos de forma automática.

---

## Lista de Verificación Previa a la Solicitud

### Fundamentos (Requeridos)

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| **Licencia FLOSS** | ✅ | Licencia MIT en el archivo `LICENSE` |
| **Sitio web del proyecto** | ✅ | Repositorio GitHub |
| **Documentación** | ✅ | README.md + docs/ |
| **Cómo contribuir** | ✅ | CONTRIBUTING.md |
| **Licencia en el repositorio** | ✅ | Archivo LICENSE |

### Control de Cambios

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| **Control de versiones** | ✅ | Git |
| **IDs de versión únicos** | ✅ | Etiquetas Git + semver |
| **Notas de versión** | ✅ | CHANGELOG.md / GitHub Releases |

### Reportes

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| **Proceso de reporte de errores** | ✅ | GitHub Issues |
| **Reporte de vulnerabilidades de seguridad** | ✅ | SECURITY.md |

### Calidad

| Criterio | Estado | Cómo Habilitar |
|----------|--------|----------------|
| **Sistema de compilación funcional** | ✅ | CI de GitHub Actions |
| **Suite de pruebas automatizada** | ⚠️ | Agregar `osdo scan` a CI |
| **Cobertura de suite de pruebas** | ⚠️ | Agregar reporte de cobertura |
| **Idioma inglés** | ✅ | Documentación en inglés |

### Seguridad

| Criterio | Estado | Cómo Habilitar |
|----------|--------|----------------|
| **Conocimiento de desarrollo seguro** | ✅ | SECURITY.md documenta prácticas |
| **Comunicaciones seguras** | ✅ | Solo HTTPS |
| **Análisis estático** | ✅ | osdo-sast en CI |
| **Corregir vulns críticas en 60 días** | ⚠️ | Habilitar osdo-sca + Dependabot |

### Análisis

| Criterio | Estado | Cómo Habilitar |
|----------|--------|----------------|
| **Análisis estático** | ✅ | osdo-sast |
| **Advertencias atendidas** | ⚠️ | Corregir hallazgos antes de la versión |

---

## Archivos Requeridos

### SECURITY.md

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities via GitHub Security Advisories:
https://github.com/YOUR_ORG/YOUR_REPO/security/advisories

Do NOT open public issues for security vulnerabilities.

## Security Practices

- Static analysis: Semgrep, Bandit
- Dependency scanning: OSV-Scanner, Grype
- Container scanning: Trivy
- Secrets detection: Gitleaks
```

### CONTRIBUTING.md

```markdown
# Contributing

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security scans: `osdo scan`
5. Submit a pull request

## Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## Security

See SECURITY.md for vulnerability reporting.
```

---

## GitHub Actions para Requisitos de la Insignia

Agrega esto a tu workflow para cumplir los requisitos:

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Requisito: Suite de pruebas automatizada
      - name: Run Tests
        run: make test

      # Requisito: Cobertura de pruebas
      - name: Coverage Report
        run: make coverage

      # Requisito: Análisis estático
      - uses: opensecdevops/osdo-actions/osdo-sast@v2

      # Requisito: Escaneo de vulnerabilidades conocidas
      - uses: opensecdevops/osdo-actions/osdo-sca@v2
```

---

## Envío de tu Solicitud

### Paso 1: Crear Cuenta

Visita [bestpractices.coreinfrastructure.org](https://bestpractices.coreinfrastructure.org/) e inicia sesión con GitHub.

### Paso 2: Agregar Proyecto

Haz clic en "Get Your Badge Now" e ingresa la URL de tu repositorio.

### Paso 3: Responder Preguntas

El cuestionario cubre:
- **Fundamentos** (14 preguntas)
- **Control de Cambios** (5 preguntas)
- **Reportes** (6 preguntas)
- **Calidad** (13 preguntas)
- **Seguridad** (16 preguntas)
- **Análisis** (4 preguntas)

### Paso 4: Proporcionar Evidencia

Para cada criterio, proporciona:
- URL al archivo (ej., SECURITY.md)
- URL al workflow de CI
- Breve explicación

### Respuestas de Ejemplo

| Pregunta | Respuesta |
|----------|-----------|
| ¿Cuál es tu proceso de divulgación de seguridad? | [Enlace a SECURITY.md] - Reportar vía GitHub Security Advisories |
| ¿Usas herramientas de análisis estático? | Sí - osdo-sast ejecuta Semgrep en cada PR [Enlace al workflow] |
| ¿Corriges vulnerabilidades críticas? | Sí - osdo-sca alerta sobre vulns críticas, rastreadas en Issues |

---

## Comandos de Verificación

Antes de enviar, verifica localmente:

```bash
# Verificar cumplimiento general
osdo certify --standard openssf

# Verificar que el escaneo de seguridad funciona
osdo scan

# Verificar archivos requeridos
ls README.md SECURITY.md CONTRIBUTING.md LICENSE

# Verificar que CI pasa
git push && # Revisar GitHub Actions
```

---

## Niveles de Insignia

| Nivel | Requisitos | Tiempo para Obtener |
|-------|------------|---------------------|
| **Passing** | Criterios básicos | 1-2 horas con OSDO |
| **Silver** | Passing + mejorado | Semana adicional |
| **Gold** | Silver + avanzado | Mes adicional |

---

## Inicio Rápido

```bash
# 1. Inicializar proyecto con archivos requeridos
osdo init --template web-api --name myproject

# 2. Verificar cumplimiento
osdo certify --standard openssf

# 3. Corregir brechas
# (Seguir recomendaciones de la salida de certify)

# 4. Enviar en bestpractices.coreinfrastructure.org
```

---

## Ver También

- [Criterios de la Insignia OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/en/criteria)
- [Listas de Verificación de Certificación OSDO](CERTIFICATION_CHECKLISTS.md)
- [De 0 a OSDO en 1 Hora](QUICKSTART.md)
