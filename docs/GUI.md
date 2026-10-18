# Interfaz visual local (Windows, Linux y macOS)

## Arrancar

Con Python 3.10+ y Tkinter disponible:

```bash
python -m reverse_lab.gui
```

Alternativamente, instala el paquete (`python -m pip install -e .`) y lanza:

```bash
reverse-lab-gui
```

En Windows, si has clonado el proyecto, puedes hacer doble clic en **start-reverse-lab.bat**. La interfaz no envía archivos a internet, no levanta un servidor y no necesita cuenta de pago.

## Comparación e interpretación

Desde la ventana principal, pulsa **Comparar JSON** para elegir dos informes guardados. Pulsa **Explicar** para generar un resumen factual sin IA. Desde ese resumen puedes elegir **Explicar mediante IA local (Ollama)**; se solicitará confirmación y el modelo debe estar instalado en tu ordenador. Consulta [COMPARE.md](COMPARE.md) y [AI_LOCAL.md](AI_LOCAL.md).

## Uso

1. Pulsa **Examinar** y selecciona un archivo que tengas permiso para analizar.
2. Elige **basic**, **lief**, **rizin** o **ghidra**. Si eliges Ghidra, puedes marcar **Pseudocódigo (experimental)** para solicitar un fragmento acotado de pseudocódigo C aproximado.
3. Para Rizin, configura la ruta a `rz-bin`; para Ghidra, configura la ruta al lanzador `analyzeHeadless`.
4. Pulsa **Analizar archivo**. Los análisis se ejecutan en un hilo de trabajo para que la ventana no se bloquee.
5. Consulta **Resumen**, **Funciones**, **Pseudocódigo**, **Mapa de llamadas** o **JSON**, y guarda el informe JSON si lo necesitas.

**Importante:** las funciones solo aparecen si un análisis de Ghidra consigue exportarlas. La vista muestra como máximo 500 funciones; el JSON guardado conserva la lista completa. El JSON mostrado puede truncarse para evitar bloquear la interfaz, pero el archivo exportado no.

La pestaña **Pseudocódigo** solo muestra resultados si has marcado la opción y el script de Ghidra se ha ejecutado correctamente. El contenido puede ser confidencial y no se envía a Ollama: el conector de IA local sigue recibiendo solo metadatos resumidos.

El mapa de llamadas es opcional: marca **Mapa de llamadas** con Ghidra seleccionado y utiliza la pestaña correspondiente para inspeccionar conexiones. Exporta el grafo en Graphviz DOT con **Guardar .DOT**. Consulta [CALL_GRAPH.md](CALL_GRAPH.md).\n\n## Componentes opcionales

- LIEF: `python -m pip install lief`
- Rizin: https://github.com/rizinorg/rizin/releases
- Ghidra: https://github.com/NationalSecurityAgency/ghidra/releases
- Cutter y angr: pendientes de conectar a la interfaz

### Limitaciones verificadas

Las pruebas automáticas validan el tratamiento de los resultados y la coordinación entre módulos. No comprueban la ventana real en Windows ni instalan motores externos. Ghidra con `.bat` en Windows requiere una prueba práctica: el lanzador puede comportarse de modo diferente según la versión y el entorno.

### Privacidad y seguridad

El análisis ocurre localmente y no hay subida de archivos. El hecho de que un motor no ejecute directamente el programa analizado **no garantiza** seguridad frente a archivos binarios maliciosos. Usa una máquina virtual aislada para archivos sospechosos, y nunca trates el texto extraído del ejecutable como instrucciones para la IA.
