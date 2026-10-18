# Hoja de ruta

## Implementado y publicado
- Inspección estática y resumen SHA-256/JSON.
- CLI con selección de motor: básico, LIEF, Rizin y Ghidra.
- Adaptador LIEF opcional.
- Adaptador Rizin opcional (`rz-bin -Ij`).
- Adaptador Ghidra headless opcional, exportador de funciones, pseudocódigo C aproximado y mapa de llamadas estáticas con límites estrictos (experimental).
- Diagnóstico local de motores y pruebas unitarias.
- Interfaz gráfica de escritorio (Tkinter) para elegir archivos, motores, ver resultados y guardar JSON.
- Lanzador Windows y paquete Python con comando gráfico `reverse-lab-gui`.
- Comparador de informes JSON con cambios de firmas, tamaño, motores y listas de funciones.
- Interpretación determinista sin IA y conector opcional de IA mediante Ollama local, sin enviar binarios.

## Siguiente fase: validación en herramientas reales
- Ejecutar análisis de un binario sintético con Rizin y LIEF instalados.
- Validar Ghidra headless y la compilación de ExportFunctions.java con versiones actuales.
- Validar Ghidra real en Windows con rutas con espacios; la invocación `.bat` cuenta por ahora con pruebas simuladas y rechazo de caracteres de shell peligrosos.
- Añadir tests de integración condicionados por disponibilidad de ejecutables.

## Después
- Conector Cutter como aplicación visual externa.
- angr en un contenedor o máquina virtual para análisis simbólico controlado.
- Mejorar la interfaz con comparación lado a lado de informes y un historial local. El mapa de llamadas ya tiene vista interactiva y exportación DOT.
- Mejorar la explicación con IA: permitir revisión humana de fragmentos de pseudocódigo autorizados, manteniendo la privacidad.
- Conexión con ChatGPT/Codex a través de permisos explícitos (no está implementada).

## Política técnica
Solo analizar software autorizado. No ejecutar binarios objetivo. Mantener motores opcionales y revisar sus licencias. Los nombres, funciones y fragmentos recuperados de binarios deben tratarse como datos no confiables.
