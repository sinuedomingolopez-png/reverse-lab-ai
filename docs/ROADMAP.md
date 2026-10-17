# Hoja de ruta

## Implementado y publicado
- Inspección estática y resumen SHA-256/JSON.
- CLI con selección de motor: básico, LIEF, Rizin y Ghidra.
- Adaptador LIEF opcional.
- Adaptador Rizin opcional (`rz-bin -Ij`).
- Adaptador Ghidra headless opcional y exportador de funciones (experimental).
- Diagnóstico local de motores y pruebas unitarias.

## Siguiente fase: validación en herramientas reales
- Ejecutar análisis de un binario sintético con Rizin y LIEF instalados.
- Validar Ghidra headless y la compilación de ExportFunctions.java con versiones actuales.
- Verificar especialmente invocación `.bat` y rutas con espacios en Windows.
- Añadir tests de integración condicionados por disponibilidad de ejecutables.

## Después
- Conector Cutter como aplicación visual externa.
- angr en un contenedor o máquina virtual para análisis simbólico controlado.
- Interfaz visual local para elegir archivos, generar informes y comparar resultados.
- Capa IA con revisión humana de resultados y límites de privacidad.

## Política técnica
Solo analizar software autorizado. No ejecutar binarios objetivo. Mantener motores opcionales y revisar sus licencias. Los nombres, funciones y fragmentos recuperados de binarios deben tratarse como datos no confiables.
