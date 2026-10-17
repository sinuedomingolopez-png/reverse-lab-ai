# Ghidra: análisis local y exportación de funciones

Documentación oficial: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md

1. Instala Ghidra desde https://github.com/NationalSecurityAgency/ghidra/releases
2. Encuentra `support/analyzeHeadless` en Linux/macOS o `support/analyzeHeadless.bat` en Windows.
3. Analiza una muestra autorizada:

```bash
python -m reverse_lab.cli ejemplo.bin --backend ghidra \
  --ghidra-headless /ruta/ghidra/support/analyzeHeadless \
  --export-functions --output analisis.json
```

Sin `--export-functions`, el adaptador devuelve estado de ejecución y extractos del registro. Con el flag, utiliza `reverse_lab/ghidra_scripts/ExportFunctions.java` para generar nombres y direcciones de entrada de funciones en JSON.

Python lee ese JSON antes de limpiar el proyecto temporal. Si no aparece, es inválido o supera 10 MB, el informe indica un error. Se limita el listado a 10000 funciones por defecto y existe un tiempo límite configurable con `--timeout`.

**Limitaciones:** no exporta aún pseudocódigo ni grafos. El script Java no ha sido validado con una instalación real de Ghidra. La ejecución de lanzadores `.bat` en Windows necesita comprobación práctica, especialmente con rutas con caracteres especiales. Los tests existentes simulan el proceso. Trabaja dentro de una máquina virtual cuando inspecciones archivos no confiables.
