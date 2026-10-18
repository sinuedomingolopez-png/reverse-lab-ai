# Hoja de ruta

## Implementado y publicado
- Inspección estática y resumen SHA-256/JSON.
- CLI con selección de motor: básico, LIEF, Rizin y Ghidra.
- Adaptador LIEF opcional.
- Adaptador Rizin opcional (`rz-bin -Ij`).
- Adaptador Ghidra headless opcional, exportador de funciones, pseudocódigo C aproximado y mapa de llamadas estáticas con límites estrictos (experimental).
- Integración opcional de Cutter como editor externo (confirmación de usuario).
- Adaptador angr CFGFast con worker Python separado, análisis estático de funciones y control de tiempo/tamaño.
- Diagnóstico local de motores, autoprueba opcional de Ghidra con una muestra ELF sintética y pruebas unitarias.
- Interfaz gráfica de escritorio (Tkinter) para elegir archivos, motores, ver resultados y guardar JSON.
- Explorador de funciones con búsqueda, referencias de entrada/salida, pseudocódigo, navegación entre funciones y carga local de informes anteriores.
- Lanzador Windows y paquete Python con comando gráfico `reverse-lab-gui`.
- Pipeline de ZIP portable en Windows (PyInstaller), con autoprueba offline del ejecutable, intento de arranque real de la ventana Tkinter (registrando `not_verified` cuando la CI carece de escritorio), scripts de Ghidra empaquetados y SHA-256.
- Historial optativo y local de informes con controles de privacidad, límites de tamaño y borrado explícito.
- Exportación voluntaria de diagnóstico offline sin nombres ni rutas privadas y script Windows para problemas de arranque.
- Verificación de la generación de informes de soporte mediante el EXE compilado en GitHub Actions.
- Comparador de informes JSON con cambios de firmas, tamaño, motores y listas de funciones.
- Interpretación determinista sin IA y conector opcional de IA mediante Ollama local, sin enviar binarios.

## Siguiente fase: validación en herramientas reales

- Probar el ZIP portable en Windows físico y contrastar advertencias de seguridad al ser un ejecutable **sin firma**.
- Probar acceso de la versión portable a Ghidra, Cutter y Rizin instalados en Windows.
- Probar angr externo con `REVERSE_LAB_PYTHON` y una muestra sintética en un entorno aislado.
- Ejecutar análisis de un binario sintético con Rizin y LIEF instalados.
- Ejecutar en un equipo con Ghidra instalado la nueva autoprueba y validar la compilación de los tres scripts Java con versiones actuales.
- Validar Ghidra real en Windows con rutas con espacios; la invocación `.bat` cuenta por ahora con pruebas simuladas y rechazo de caracteres de shell peligrosos.
- Añadir tests de integración condicionados por disponibilidad de ejecutables.

## Después
- Verificar Cutter instalado en Windows y mejorar intercambio voluntario de datos con Reverse Lab AI.
- Para ampliar angr a ejecución simbólica, añadir primero aislamiento más fuerte (contenedor/VM), límites de memoria y pruebas específicas; todavía no está implementado.
- Mejorar la interfaz con comparación lado a lado de informes y un historial local. El mapa de llamadas ya tiene vista interactiva y exportación DOT.
- Mejorar la explicación con IA: permitir revisión humana de fragmentos de pseudocódigo autorizados, manteniendo la privacidad.
- Conexión con ChatGPT/Codex a través de permisos explícitos (no está implementada).

## Política técnica
Solo analizar software autorizado. No ejecutar binarios objetivo. Mantener motores opcionales y revisar sus licencias. Los nombres, funciones y fragmentos recuperados de binarios deben tratarse como datos no confiables.
