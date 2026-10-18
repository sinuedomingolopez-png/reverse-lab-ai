# Mapa de llamadas — Reverse Lab AI 0.5

La función opcional **Mapa de llamadas** consulta referencias entre funciones detectadas por Ghidra. Es un análisis **estático**: no ejecuta el archivo examinado y no demuestra que todas las llamadas hayan sido identificadas.

## Requisitos

Ghidra instalado localmente y disponible mediante la ruta a `support/analyzeHeadless` (Linux/macOS) o `support/analyzeHeadless.bat` (Windows). Las herramientas externas no se instalan automáticamente.

## Analizar desde terminal

```bash
python -m reverse_lab.cli programa.bin --backend ghidra \
  --ghidra-headless /ruta/a/ghidra/support/analyzeHeadless \
  --export-functions --export-call-graph --output analisis.json
```

En Windows, cambia la ruta del ejecutable por la correspondiente a tu instalación, preferiblemente sin caracteres especiales de `cmd.exe`. El análisis está limitado por el tiempo general `--timeout`.

## Analizar desde la interfaz gráfica

1. Abre `python -m reverse_lab.gui`.
2. Selecciona **Ghidra** y configura `analyzeHeadless`.
3. Marca **Mapa de llamadas** y pulsa **Analizar archivo**.
4. Abre la pestaña **Mapa de llamadas**. Cada fila muestra quién llama a quién.
5. Selecciona una fila para visualizar la función origen y hasta 8 llamadas directas.
6. Pulsa **Guardar .DOT** para exportar el grafo con los enlaces conservados en el informe.

La tabla muestra hasta **500** relaciones por motivos de rendimiento; el informe JSON puede contener hasta **2000** por defecto. Los límites internos del adaptador son 500 funciones origen y 5000 enlaces; por defecto examina como máximo **200 funciones origen y 2000 enlaces**. La exportación a DOT incluye hasta 5000 enlaces.

Puedes renderizar el archivo DOT con la herramienta gratuita Graphviz, que se instala por separado:

```bash
dot -Tsvg llamadas.dot -o llamadas.svg
```

## Formato del JSON

Dentro de `analysis.call_graph` hay una lista de enlaces, por ejemplo:

```json
[
  {
    "caller": {"name": "main", "entry": "00401000"},
    "callee": {"name": "helper", "entry": "00401200"}
  }
]
```

Cada nombre y dirección proviene de Ghidra. Los nombres originales pueden haberse perdido y algunas funciones pueden ser renombradas automáticamente. Los resultados pueden omitir llamadas indirectas, referencias dinámicas, bibliotecas externas o destinos sin resolver. El grafo exportado **no es una prueba completa del flujo de ejecución**, y la ausencia de una arista no demuestra que una llamada no pueda ocurrir.

## Seguridad y estado

- El exportador comprueba la estructura del JSON, los límites de tamaño y el número de aristas antes de aceptarlas.
- Analiza únicamente software propio, libre o para el que dispongas de autorización. Usa una máquina virtual si el binario es desconocido.
- Los nombres y datos extraídos se tratan como **contenido no confiable**; no se envían a un modelo remoto.
- Los tests automáticos incluyen un simulador del lanzador headless. **Falta validar el script Java con una instalación real de Ghidra en Windows.**
- API oficial utilizada: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html
