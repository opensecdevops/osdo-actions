# De 0 a OSDO en 1 hora

Pon en marcha un pipeline de DevSecOps listo para producción en menos de una hora.

## 🎯 Qué construirás

Al terminar esta guía, tendrás:
- ✅ Escaneo de seguridad automatizado (SAST, SCA, Secretos)
- ✅ Generación de SBOM (SPDX + CycloneDX)
- ✅ Escaneo de seguridad de contenedores
- ✅ Aplicación de Políticas como Código
- ✅ Cumplimiento SLSA Nivel 3 (opcional)

---

## Requisitos previos

- Repositorio GitHub con código fuente
- Conocimientos básicos de GitHub Actions
- (Opcional) CLI `osdo` instalado

---

## Inicio rápido: 5 minutos

### Opción A: Usando el CLI de OSDO

```bash
# Install OSDO CLI
go install github.com/opensecdevops/osdo-infra-cli@latest

# Initialize project with Golden Path template
osdo init --template web-api --name my-project

# Done! Push and your pipeline runs automatically
git add . && git commit -m "chore: add OSDO security" && git push
```

### Opción B: Configuración manual

Crea `.github/workflows/osdo-security.yml`:

```yaml
name: OSDO Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SAST Scan
        uses: opensecdevops/osdo-actions/osdo-sast@v1

      - name: SCA Scan
        uses: opensecdevops/osdo-actions/osdo-sca@v1

      - name: Secrets Scan
        uses: opensecdevops/osdo-actions/osdo-secrets-scan@v1

      - name: Generate SBOM
        uses: opensecdevops/osdo-actions/osdo-sbom@v1
```

Confirma el commit, haz push y listo. 🎉

---

## Amplía tu pipeline: 15 minutos

### Añadir escaneo de contenedores

```yaml
  container:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Container
        run: docker build -t app:${{ github.sha }} .

      - name: Container Scan
        uses: opensecdevops/osdo-actions/osdo-container-scan@v1
        with:
          image: app:${{ github.sha }}
```

### Añadir escaneo de IaC (Terraform/Kubernetes)

```yaml
      - name: IaC Scan
        uses: opensecdevops/osdo-actions/osdo-iac-scan@v1
        with:
          path: ./deploy
          scanners: checkov,kics
```

### Añadir una puerta de políticas

```yaml
      - name: Policy Gate
        uses: opensecdevops/osdo-actions/osdo-policy-gate@v1
        with:
          builtin-policies: security,compliance
          fail-on-violation: true
```

---

## Alcanzar SLSA Nivel 3: 30 minutos

Añade seguridad en la cadena de suministro:

```yaml
  release:
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: make build

      - name: Generate Provenance
        uses: opensecdevops/osdo-actions/osdo-slsa-provenance@v1
        with:
          subject-path: dist/*
          slsa-level: "3"
```

---

## Verifica tu progreso

### Usando el CLI de OSDO

```bash
# Run local security scan
osdo scan

# Check certification readiness
osdo certify --standard owasp

# View compliance score
osdo certify --standard slsa
```

### Salida esperada

```
📋 OSDO Certification Readiness
═══════════════════════════════
Standard: OWASP Top 10 2021

✓ Access Control Testing              A01:Broken Access Control
✓ Cryptographic Configuration         A02:Cryptographic Failures
✓ Injection Prevention                A03:Injection
...

Score: 85%
✅ CERTIFICATION READY
```

---

## Próximos pasos

| Objetivo | Guía |
|----------|------|
| Añadir pruebas DAST | [Documentación osdo-dast-scan](actions/osdo-dast-scan/) |
| Añadir fuzzing | [Documentación osdo-fuzz](actions/osdo-fuzz/) |
| Desplegar infraestructura | [Documentación osdo-infra-cli](infra-cli/) |
| Políticas personalizadas | [Guía de Políticas como Código](docs/policy-gate/) |

---

## Ejemplo completo de workflow

```yaml
name: OSDO Full Pipeline

on:
  push:
    branches: [main]
  pull_request:
  release:
    types: [published]

permissions:
  contents: read
  security-events: write
  packages: write
  id-token: write

jobs:
  # Etapa 1: Escaneo de seguridad
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-sast@v1

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-sca@v1

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-secrets-scan@v1

  # Etapa 2: Build y escaneo de contenedor
  build:
    needs: [sast, sca, secrets]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t app:${{ github.sha }} .
      - uses: opensecdevops/osdo-actions/osdo-container-scan@v1
        with:
          image: app:${{ github.sha }}

  # Etapa 3: Puerta de políticas
  policy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-policy-gate@v1

  # Etapa 4: SBOM + Procedencia
  supply-chain:
    needs: policy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opensecdevops/osdo-actions/osdo-sbom@v1
      - if: github.event_name == 'release'
        uses: opensecdevops/osdo-actions/osdo-slsa-provenance@v1
        with:
          subject-path: dist/*
          slsa-level: "3"
```

---

## Solución de problemas

| Problema | Solución |
|----------|----------|
| Action no encontrada | Usa el formato `opensecdevops/osdo-actions/osdo-xxx@v1` |
| Permiso denegado | Añade `security-events: write` a los permisos |
| El escaneo falla inmediatamente | Verifica que las herramientas requeridas están en el runner |

---

## Obtener ayuda

- 📖 [Documentación completa](https://opensecdevops.dev/docs)
- 💬 [GitHub Discussions](https://github.com/opensecdevops/osdo-actions/discussions)
- 🐛 [Reportar problemas](https://github.com/opensecdevops/osdo-actions/issues)

---

**¡Es hora de proteger tu código!** 🔒
