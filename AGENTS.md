# Instrucciones para Codex — Reverse Lab AI

- Proyecto independiente de ingeniería inversa con herramientas gratuitas y preferencia por ejecución local.
- Mantén separado este repositorio de Veneno Azul, Modular Terrace y DARKROOM909; no reutilices sus secretos ni entornos.
- Empieza por análisis estático seguro. No ejecutes, importes ni cargues binarios desconocidos en el proceso principal.
- Trabaja únicamente con muestras cuyo análisis esté autorizado y respeta licencias, límites de acceso y derechos de terceros.
- Antes de integrar Ghidra, LIEF, Rizin, Cutter o angr, verifica disponibilidad, licencia, API, tamaño, costes y pruebas. No presentes herramientas previstas como integradas.
- Ejecuta `python -m unittest discover -s tests -v` y conserva tests reproducibles de tipos, cabeceras, hashes, tamaño y errores.
- Registra límites, resultados de prueba y amenazas pendientes. Los informes deben diferenciar observaciones de hipótesis.
- Prepara PRs antes de cambiar el comportamiento; no realices despliegues no solicitados.

## Windows portable

- La compilación para usuarios se crea en Windows con PyInstaller y se publica como artifact temporal de GitHub Actions.
- Nunca afirmes que está firmada digitalmente. Conserva comprobación SHA-256 y arranque `--self-test-output` sin ejecutar muestras.
- No incluyas motores Ghidra/Rizin/Cutter/LIEF/angr ni muestras privadas en el ZIP base. En modo frozen, angr requiere Python real externo configurado mediante `REVERSE_LAB_PYTHON`.
- Las compilaciones sin firma pueden activar SmartScreen: no recomiendes desactivar protecciones del sistema.

## Historia local de análisis

- Nunca guardar informes automáticamente. El historial completo (incluidos pseudocódigo y símbolos) debe requerir acción y confirmación explícitas.
- No subir informes del historial a GitHub, servicios externos ni IA; proteger identificadores, límites de archivos y operaciones de borrado.
- La versión portable debe comprobar con `--gui-smoke-output` la ventana real de Windows antes de publicar artefactos.
