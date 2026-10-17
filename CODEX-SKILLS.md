# Skills para Codex — Reverse Lab AI

El agente obtiene reglas locales en `AGENTS.md` y la skill `.agents/skills/reverse-safe-analysis/SKILL.md` tras fusionar esta propuesta.

## Habilidad principal

`reverse-safe-analysis` regula parsers, análisis estático, aislamiento de archivos no confiables y pruebas de formato. Es específica de ingeniería inversa, no una skill de despliegue web. El proyecto debe seguir trabajando con software gratuito y análisis autorizado.

## Futuras integraciones

Ghidra, LIEF, Rizin, Cutter y angr son **opciones por evaluar**, no dependencias confirmadas. Cada integración deberá incluir detección de herramienta, compatibilidad, licencia y tests reproducibles. No se ejecutarán ejecutables de terceros para identificarlos por defecto.

## Comprobación

Tras modificar Python, ejecutar: `python -m unittest discover -s tests -v`. Reunir evidencia antes de dar por implementada una función. Nunca publicar muestras o secretos; preparar PRs para revisión.

Para descubrir skills generales de desarrollo, usar [skills.sh](https://skills.sh/), revisar el código de la skill antes de instalar y evitar paquetes irrelevantes para análisis local. Estas instrucciones no requieren ningún servicio de pago.
