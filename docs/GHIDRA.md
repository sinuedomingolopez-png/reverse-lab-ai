# Ghidra: análisis local y exportación de funciones y pseudocódigo experimental

Documentación oficial: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md

1. Instala Ghidra desde https://github.com/NationalSecurityAgency/ghidra/releases
   y comprueba que tengas la versión de Java/JDK exigida por ese lanzamiento.
2. Encuentra `support/analyzeHeadless` en Linux/macOS o `support/analyzeHeadless.bat` en Windows.
3. Analiza una muestra autorizada:

```bash
python -m reverse_lab.cli ejemplo.bin --backend ghidra \
  --ghidra-headless /ruta/ghidra/support/analyzeHeadless \
  --export-functions --export-pseudocode --export-call-graph --output analisis.json
```

### Autoprueba previa

Antes de analizar tus propios programas, utiliza la [autoprueba de integración](GHIDRA_SELFTEST.md):

```bash
python -m reverse_lab.ghidra_probe --check-only
python -m reverse_lab.ghidra_probe --ghidra-headless /ruta/ghidra/support/analyzeHeadless --output diagnostico-ghidra.json
```

Sin `--export-functions`, el adaptador devuelve estado de ejecución y extractos del registro. Con el flag, utiliza `reverse_lab/ghidra_scripts/ExportFunctions.java` para generar nombres y direcciones de entrada de funciones en JSON.

`--export-pseudocode` añade el script `ExportPseudocode.java`, que utiliza el descompilador de Ghidra para obtener pseudocódigo C aproximado. Está desactivado por defecto y limitado a 20 funciones, 8000 caracteres por función y 10 segundos por función. Se comprueba que el JSON no exceda 2 MiB; las entradas se validan antes de aceptarlas. **No recupera el código fuente original.**

Python lee el JSON antes de limpiar el proyecto temporal. Si no aparece, es inválido o supera 10 MB, el informe indica un error. Se limita el listado a 10000 funciones por defecto y existe un tiempo límite configurable con `--timeout`.

El flag `--export-call-graph` ejecuta `ExportCallGraph.java` y obtiene relaciones estáticas entre funciones, con un máximo por defecto de 200 funciones origen y 2000 aristas. La nueva pestaña «Mapa de llamadas» muestra y exporta el resultado a DOT. Consulta [CALL_GRAPH.md](CALL_GRAPH.md).

**Limitaciones:** la exportación de pseudocódigo es experimental y no se ha probado aún con un Ghidra real. Las pruebas incluyen un ejecutable de análisis simulado y comprobaciones de argumentos en Windows. El lanzador `.bat` emplea la ruta de shell de Python con validación previa y rechaza rutas que contienen `&`, `|`, `<`, `>`, `^`, `%` o `!`. Falta realizar una prueba real de extremo a extremo en Windows. Los archivos desconocidos deben analizarse dentro de una máquina virtual sin acceso a información privada. El JSON con pseudocódigo **puede contener secretos del archivo**, por lo que no debes publicarlo ni cargarlo automáticamente en modelos remotos. Trabaja dentro de una máquina virtual cuando inspecciones archivos no confiables.
