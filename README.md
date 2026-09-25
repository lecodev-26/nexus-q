# AXIOM NEXUS-Q

> Post-quantum cryptographic security engine for protecting data, keys, and identities.

**Estado**: 🚧 En desarrollo activo — Fase 0 (Fundaciones)

---

## ¿Qué es NEXUS-Q?

NEXUS-Q es un motor de seguridad criptográfica post-cuántica diseñado para proteger:

- **Datos** — cifrado autenticado de archivos y flujos
- **Claves** — gestión completa de ciclo de vida (generación, rotación, revocación, destrucción)
- **Identidades** — firmas digitales y credenciales verificables

Está pensado para ser usado por:

- Aplicaciones (Web, Server, Mobile)
- Servidores
- Dispositivos con hardware seguro (TPM, HSM, Secure Element, RISC-V, Enclave)

---

## Principios de diseño

1. **No inventamos criptografía.** Solo algoritmos estandarizados y bibliotecas auditadas.
2. **Library-first.** El núcleo es una librería Rust; el CLI, la API y el server son capas encima.
3. **Hardware-agnóstico.** Abstracción desde el día 1 para soportar software, TPM, HSM y entornos seguros.
4. **Zeroización.** Los secretos se destruyen en memoria cuando es viable.
5. **Trazabilidad.** Toda operación sensible queda en un audit log.
6. **Seguridad desde los cimientos.** Threat model y reglas criptográficas antes que código.

---

## Arquitectura (visión)

```

┌─────────────────────────┐
│       Aplicaciones      │
│ Web / Server / Mobile   │
└────────────┬────────────┘
│
SDK / API / CLI
│
┌────────────▼────────────┐
│      NEXUS-Q CORE       │
│                         │
│ Crypto │ Vault │ ID     │
│ Policy │ Storage │ Audit │
└─────┬─────────┬─────────┘
│         │
┌─────▼───┐ ┌──▼───────────┐
│Software │ │  Hardware    │
│Backend  │ │  Backend     │
└─────────┘ └──────────────┘
│
┌──────────▼─────────┐
│ TRNG / HSM / TPM   │
│ Secure Element     │
│ RISC-V / Enclave   │
└────────────────────┘

```

---

## Estado del proyecto

Fase actual: **Fase 0 — Fundaciones**

- [x] Estructura inicial del repositorio
- [ ] Documentación de arquitectura
- [ ] Threat model
- [ ] Reglas criptográficas
- [ ] Definición de alcance de v1.0

Ver [`docs/ROADMAP.md`](docs/ROADMAP.md) para el plan completo.

---

## Requisitos

- **Rust** 1.98+ (edition 2024)
- **Clang** 21+
- **Git** 2.55+
- Plataformas objetivo:
  - Linux (x86_64, aarch64)
  - Android / Termux (aarch64)
  - macOS (futuro)
  - Windows (futuro)

---

## Compilación

> Aún no hay código funcional. Esta sección se completará en la Fase 1.

```bash
# (pendiente)
cargo build
cargo test
```

---

Documentación

Toda la documentación técnica vive en docs/:

· ARCHITECTURE.md — diseño del sistema
· THREAT_MODEL.md — contra qué nos protegemos
· CRYPTOGRAPHY.md — algoritmos y reglas
· KEY_MANAGEMENT.md — ciclo de vida de claves
· SECURITY_MODEL.md — modelo de seguridad
· STORAGE.md — almacenamiento persistente
· API.md — interfaces públicas
· ROADMAP.md — plan por fases

---

## Licencia

Dual-licensed bajo tu elección de:

- **MIT License** — ver [`LICENSE-MIT`](LICENSE-MIT)
- **Apache License 2.0** — ver [`LICENSE-APACHE`](LICENSE-APACHE)

Esto sigue la convención del ecosistema Rust (misma elección que Rust, Tokio, Serde).

---

## Aviso

Este proyecto está en fase temprana de desarrollo. No usar en producción todavía.
