# Ghidra: análisis local

1. Instala Ghidra desde su repositorio oficial: https://github.com/NationalSecurityAgency/ghidra
2. Localiza el ejecutable analyzeHeadless (en Windows: support/analyzeHeadless.bat).
3. Ejecuta el adaptador desde Python:

```python
from reverse_lab.integrations.ghidra_adapter import analyze_with_ghidra
report = analyze_with_ghidra("sample.bin", r"C:\ghidra\support\analyzeHeadless.bat")
print(report)
```

El adaptador invoca Ghidra headless, captura un resumen de la salida y elimina el proyecto temporal. Todavía no exporta pseudocódigo ni grafos. No procesa archivos no confiables fuera de un entorno aislado: un analizador puede contener vulnerabilidades. En Windows puede requerirse invocar el lanzador .bat mediante cmd.exe; esa compatibilidad aún no está implementada.
