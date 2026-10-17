# Plan técnico

## Etapa 1 (implementada)
Detector de cabeceras, resumen SHA-256, informe JSON, CLI y pruebas.

## Etapa 2
Adaptador opcional LIEF, verificación de formatos y metadatos. Pruebas con ejecutables sintéticos.

## Etapa 3
Adaptador de Ghidra headless sobre instalaciones locales, sin ejecutar los archivos objetivo. Límites de tiempo y recursos.

## Etapa 4
Rizin como motor secundario; exportación estructurada con validación.

## Etapa 5
angr en entorno aislado para análisis simbólico; Cutter como herramienta visual independiente.

## Política de integración
Solo componentes legales y autorizados; revisión de licencias, dependencias y seguridad. No incorporar el código fuente de los motores en este repositorio salvo necesidad y compatibilidad demostradas.
