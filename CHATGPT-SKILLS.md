# Biblioteca de Skills para ChatGPT y Codex

Fecha de organización: 17 de octubre de 2026.

Estas Skills son **archivos de instrucciones** guardados en GitHub. Un asistente GPT que disponga de acceso de lectura a un repositorio puede consultar su `SKILL.md` durante una conversación normal y aplicar sus reglas. Esto **no** significa que se instalen automáticamente en ChatGPT, que se ejecuten solas ni que concedan permisos o herramientas nuevos.

## Cómo utilizarlas en ChatGPT sin Codex ni Work

1. Indica el proyecto y la tarea: «Revisa el DAW de Veneno Azul usando nuestra Skill de audio».
2. El asistente consulta la Skill actual y el `AGENTS.md` del repositorio correspondiente a través de GitHub, si la conexión está disponible.
3. Analiza archivos existentes, ejecuta los tests disponibles y propone cambios o crea una rama/PR según los permisos de las herramientas.
4. Confirma con evidencia qué se ha comprobado. No atribuye a una Skill capacidades que no existen, como un control del DAW sin una API real.
5. Verifica proyecto, cuenta y entorno antes de cualquier despliegue o publicación; no mezcla secretos ni recursos entre repositorios.

Si GitHub no está conectado o el archivo no es accesible, hay que decirlo claramente. Se puede pegar o adjuntar el `SKILL.md` manualmente.

La referencia de cada Skill está en su propio proyecto; se consulta el archivo vigente en la rama indicada, no una copia que pudiera quedarse anticuada.

## Skills de este proyecto

- [reverse-safe-analysis](https://github.com/sinuedomingolopez-png/reverse-lab-ai/blob/main/.agents/skills/reverse-safe-analysis/SKILL.md): Análisis estático autorizado de archivos, parsers, adaptadores y tests.

## Reglas de alcance

Preferir ejecución local y gratuita, no ejecutar muestras desconocidas, no mezclar credenciales o repositorios y no afirmar que los motores externos están instalados por aparecer mencionados.

Consulta además [AGENTS.md](https://github.com/sinuedomingolopez-png/reverse-lab-ai/blob/main/AGENTS.md) y [CODEX-SKILLS.md](https://github.com/sinuedomingolopez-png/reverse-lab-ai/blob/main/CODEX-SKILLS.md) para el contexto técnico. Este documento es un índice; las fuentes ejecutivas son las Skills y el código real.
