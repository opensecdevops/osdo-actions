# Changelog — osdo-actions

Todos los cambios notables se documentan aquí. Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

---

## [2.0.0] - 2026-Q2 (En desarrollo)

### Añadido

- `osdo-build-security` — Build seguro con SBOM integrado
- `osdo-fuzz` — Fuzzing para Go, Python, Rust, JavaScript y C/C++
- `osdo-policy-gate` — Policy-as-code con OPA y Kyverno
- `osdo-security-gate` — Quality gate de seguridad configurable
- `osdo-setup-env` — Setup de entorno con cache optimizado
- `osdo-slsa-provenance` — SLSA Level 3 con Sigstore/Cosign y Rekor
- `osdo-smart-contract-audit` — Auditoría de smart contracts (Slither, Mythril, Solhint)
- `osdo-sign` — Firma de artefactos con cosign y attestation
- Documentación completa en español para las 22 acciones
- JSON Schema para validación de `.osdo/config.yaml`
- Integración con OSDO App para centralizar el historial de escaneos, tendencias de hallazgos y dashboards de cumplimiento

### Cambiado

- BREAKING: Versionado cambia de `@main` a `@v2.x.x` para todas las acciones
- Todas las acciones ahora usan `set -euo pipefail` en todos los shells

### Corregido

- `publish.yml` ahora incluye las 22 acciones (antes sólo listaba 14)

---

## [1.0.0] - 2025-12-14

### Lanzamiento Público Inicial

Primera versión estable y disponible públicamente de OSDO Actions. Este lanzamiento incluye **22 acciones de GitHub** listas para producción, organizadas en cinco categorías funcionales que cubren el ciclo completo de seguridad en pipelines de CI/CD.

---

### Acciones Publicadas

#### Análisis de Código

Acciones orientadas al análisis de seguridad del código fuente y sus dependencias.

- **`osdo-sast`**
  Análisis Estático de Seguridad de Aplicaciones (SAST). Integra múltiples motores de análisis estático (incluyendo Semgrep y Bandit) para detectar vulnerabilidades, patrones inseguros y _code smells_ de seguridad en el código fuente del repositorio. Soporta múltiples lenguajes de programación y genera resultados en formato SARIF compatible con GitHub Code Scanning.

- **`osdo-sca`**
  Análisis de Composición de Software (SCA). Escanea las dependencias del proyecto en busca de vulnerabilidades conocidas utilizando bases de datos como OSV, NVD y advisories de GitHub. Soporta ecosistemas npm, pip, Go modules, Maven, Gradle, Cargo y más. Genera reportes de dependencias vulnerables con indicación de severidad CVSS y versiones con parche disponible.

- **`osdo-secrets-scan`**
  Detección de secretos y credenciales expuestas en el código fuente, historial de commits y archivos de configuración. Integra Gitleaks y reglas personalizadas para identificar tokens de API, claves SSH, credenciales de bases de datos, certificados privados y otros secretos sensibles antes de que lleguen a ramas principales o entornos de producción.

---

#### Infraestructura y Contenedores

Acciones para el análisis de seguridad de imágenes de contenedor, infraestructura como código y artefactos de construcción.

- **`osdo-container-scan`**
  Escaneo de seguridad de imágenes de contenedor. Analiza imágenes Docker/OCI en busca de vulnerabilidades conocidas en paquetes del sistema operativo y dependencias de aplicación utilizando Grype y Trivy. Soporta escaneo de imágenes locales, registros remotos (Docker Hub, GHCR, ECR, GCR, ACR) y artefactos construidos durante el pipeline. Genera resultados en formato SARIF y tabla resumen.

- **`osdo-iac-scan`**
  Análisis de seguridad de Infraestructura como Código (IaC). Evalúa configuraciones de Terraform, CloudFormation, Kubernetes manifests, Helm charts, Ansible playbooks y Dockerfile en busca de malas prácticas de seguridad, configuraciones inseguras por defecto y desviaciones de los benchmarks CIS. Integra Trivy, Checkov y reglas personalizadas de OSDO.

- **`osdo-build-security`**
  Fortalecimiento de la seguridad del proceso de construcción (_build hardening_). Verifica que el entorno de construcción cumpla con las prácticas recomendadas de seguridad: uso de acciones de terceros con hash SHA fijo, ausencia de permisos excesivos en el workflow, configuración de `GITHUB_TOKEN` con mínimo privilegio, y validación de la integridad del entorno de construcción.

---

#### Cadena de Suministro

Acciones para la seguridad de la cadena de suministro de software, generación de evidencia de procedencia y control de políticas.

- **`osdo-sbom`**
  Generación de Lista de Materiales de Software (SBOM). Produce un inventario completo y estandarizado de todos los componentes de software del proyecto en formatos CycloneDX (JSON/XML) y SPDX. El SBOM incluye dependencias directas e indirectas, identificadores de licencias, versiones y hashes de integridad. Puede adjuntarse como artefacto del pipeline o publicarse en el repositorio.

- **`osdo-slsa-provenance`**
  Generación de attestation de procedencia conforme al framework SLSA (_Supply chain Levels for Software Artifacts_). Produce un documento firmado criptográficamente que prueba cómo, cuándo y desde dónde fue construido un artefacto, cumpliendo con los requisitos de SLSA Level 1, 2 y 3. Compatible con el verificador oficial de SLSA.

- **`osdo-sign`**
  Firma digital de artefactos de software. Integra Cosign y Sigstore para firmar imágenes de contenedor, binarios, SBOMs y attestations sin necesidad de gestionar claves privadas manualmente (_keyless signing_). Las firmas quedan registradas en el log de transparencia pública Rekor, permitiendo verificación independiente en cualquier momento.

- **`osdo-policy-gate`**
  Evaluación y aplicación de políticas de seguridad (_policy as code_). Define umbrales de calidad de seguridad que el pipeline debe cumplir para continuar: número máximo de vulnerabilidades por severidad, ausencia de secretos, cumplimiento de licencias, presencia de SBOM, entre otros. Integra OPA (Open Policy Agent) y políticas predefinidas de OSDO. Si las políticas no se cumplen, el pipeline falla con un reporte detallado.

- **`osdo-fuzz`**
  Pruebas de seguridad por _fuzzing_. Ejecuta pruebas de fuzzing automatizadas para descubrir vulnerabilidades de seguridad como desbordamientos de búfer, condiciones de carrera y manejo incorrecto de entradas inesperadas. Integra con OSS-Fuzz, libFuzzer y AFL++ según el lenguaje del proyecto. Los _corpus_ de fuzzing se almacenan y enriquecen entre ejecuciones del pipeline.

---

#### Pruebas y Calidad

Acciones para pruebas de seguridad dinámicas, calidad de código, reportes de cumplimiento y configuración del entorno.

- **`osdo-test-quality`**
  Evaluación de la calidad de las pruebas de seguridad del proyecto. Analiza la cobertura de pruebas, la presencia de pruebas de seguridad específicas (validación de entradas, autenticación, autorización), y verifica que las pruebas existentes no sean superficiales. Genera un reporte de calidad con recomendaciones para mejorar la postura de seguridad a nivel de pruebas.

- **`osdo-security-gate`**
  Puerta de calidad de seguridad global del pipeline. Agrega los resultados de todas las acciones de escaneo ejecutadas previamente y aplica una decisión final de aprobación o rechazo basada en umbrales configurables. Actúa como punto central de decisión antes del despliegue, garantizando que ningún artefacto con hallazgos de seguridad no resueltos llegue a producción.

- **`osdo-compliance-report`**
  Generación de reportes de cumplimiento normativo. Evalúa el repositorio y los resultados de seguridad contra marcos de referencia como OWASP Top 10, NIST SSDF, CIS Controls y SOC 2. Genera un reporte estructurado en formato HTML, PDF o Markdown con el nivel de cumplimiento, hallazgos, controles cubiertos y áreas de mejora para auditorías internas y externas.

- **`osdo-setup-env`**
  Configuración y preparación del entorno de OSDO para el pipeline. Instala y configura todas las herramientas necesarias para ejecutar las acciones de OSDO (Semgrep, Trivy, Grype, Cosign, etc.), gestiona las versiones de las herramientas, configura caché para acelerar ejecuciones posteriores y valida que el entorno cumple con los requisitos mínimos de OSDO.

- **`osdo-dast-scan`**
  Pruebas Dinámicas de Seguridad de Aplicaciones (DAST). Ejecuta pruebas de seguridad contra una instancia en ejecución de la aplicación para descubrir vulnerabilidades que solo son visibles en tiempo de ejecución: inyecciones SQL/NoSQL/LDAP, XSS, CSRF, problemas de autenticación y sesión, exposición de información sensible, etc. Integra OWASP ZAP en modo automatizado.

- **`osdo-api-scan`**
  Análisis de seguridad de APIs REST, GraphQL y gRPC. Realiza pruebas de seguridad sobre las interfaces de programación de la aplicación utilizando la especificación OpenAPI/Swagger como entrada. Detecta vulnerabilidades del OWASP API Top 10, problemas de autorización a nivel de objeto y función, y exposición excesiva de datos. Compatible con entornos de staging y previews de pull request.

---

#### Especializado

Acciones para análisis de seguridad en dominios tecnológicos especializados.

- **`osdo-mobile-scan`**
  Análisis de seguridad de aplicaciones móviles. Soporta aplicaciones Android (APK/AAB) e iOS (IPA). Realiza análisis estático del binario, inspección del manifiesto, detección de permisos excesivos, análisis de almacenamiento inseguro, comunicaciones inseguras y uso de APIs deprecated o vulnerables. Integra MobSF (Mobile Security Framework) en modo CI.

- **`osdo-smart-contract-audit`**
  Auditoría de seguridad de contratos inteligentes (_smart contracts_). Analiza contratos escritos en Solidity (Ethereum/EVM), Rust (Solana/NEAR) y otros lenguajes de blockchain en busca de vulnerabilidades conocidas: reentrancy, integer overflow/underflow, acceso no controlado, front-running, problemas de aleatoriedad, y desviaciones de los estándares de seguridad de OpenZeppelin. Integra Slither, Mythril y herramientas del ecosistema.

- **`osdo-llm-scan`**
  Análisis de seguridad de aplicaciones que integran Modelos de Lenguaje Grande (LLMs). Evalúa el código y la configuración de aplicaciones que utilizan APIs de LLMs (OpenAI, Anthropic, Cohere, modelos open-source) en busca de vulnerabilidades específicas del OWASP LLM Top 10: prompt injection, insecure output handling, training data poisoning, model theft, y otras. Inspecciona prompts del sistema, manejo de respuestas y controles de seguridad implementados.

- **`osdo-cloud-scan`**
  Análisis de postura de seguridad en la nube (_Cloud Security Posture Management_, CSPM). Evalúa configuraciones de recursos en AWS, GCP y Azure en busca de malas prácticas de seguridad: buckets S3 públicos, grupos de seguridad permisivos, rotación de claves desactivada, cifrado en reposo ausente, logging deshabilitado, entre otros. Requiere credenciales de solo lectura configuradas como secretos del repositorio.

- **`osdo-license-scan`**
  Análisis y cumplimiento de licencias de software. Identifica las licencias de todas las dependencias directas e indirectas del proyecto y verifica la compatibilidad con la licencia del proyecto y las políticas corporativas definidas. Detecta dependencias con licencias restrictivas (GPL, AGPL, LGPL) en proyectos propietarios, licencias desconocidas o dependencias sin licencia declarada. Genera un SBOM enriquecido con información de licencias.

---

### Notas de la Versión 1.0.0

- Todas las acciones son compatibles con GitHub Actions runners `ubuntu-latest` (Linux x64).
- Las acciones soportan configuración mediante el archivo `.osdo/config.yaml` en la raíz del repositorio.
- Cada acción genera artefactos de resultados en formato SARIF 2.1, CycloneDX y/o JSON propio de OSDO.
- Los resultados SARIF son automáticamente subidos a GitHub Code Scanning cuando el repositorio tiene esta función habilitada.
- Consulta la documentación completa en el directorio `docs/` y en la [wiki del proyecto](https://github.com/opensecdevops/osdo/wiki).
- Para reportar problemas o solicitar nuevas características, abre un _issue_ en [https://github.com/opensecdevops/osdo/issues](https://github.com/opensecdevops/osdo/issues).

---

_Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/) — Versionado Semántico [SemVer](https://semver.org/lang/es/)._
