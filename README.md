# Reverse Lab AI

Laboratorio gratuito y extensible de ingeniería inversa local, con análisis estático y motores opcionales.

## Interfaz visual local (0.2.0)

La aplicación de escritorio permite elegir archivos y motores, consultar el resumen técnico y las funciones exportadas por Ghidra, y guardar los informes JSON. No necesita navegador, cuenta, servidor ni pago.

```bash
python -m reverse_lab.gui
```

En Windows puedes hacer doble clic en `start-reverse-lab.bat` desde la carpeta clonada. Si existe `.venv`, se utilizará su Python. Consulta la [guía de la interfaz gráfica](docs/GUI.md).

La ventana se ha abierto en un entorno de pruebas Linux; falta validarla en Windows con herramientas reales instaladas.

## Funciones implementadas

- Identificación básica de archivos PE (posible), ELF, Mach-O (posible), WebAssembly y ZIP.
- Tamaño de archivo, SHA-256 e informes JSON.
- Adaptador LIEF para metadatos del binario (requiere instalar LIEF).
- Adaptador Rizin con `rz-bin -Ij` para metadatos JSON (requiere Rizin).
- Adaptador Ghidra headless (requiere Ghidra) y exportador experimental de nombres y direcciones de funciones.
- Diagnóstico local de LIEF, Ghidra, Rizin, Cutter y angr (sin instalarlos).
- Motor de análisis compartido por CLI e interfaz visual local con trabajos en segundo plano.
- Pruebas unitarias sin motores externos y workflow CI.

## Inicio rápido (Python 3.10+)

```bash
python -m unittest discover -s tests -v
python -m reverse_lab.doctor
python -m reverse_lab.cli README.md --output informe.json
```

### Análisis con LIEF (opcional)

```bash
python -m pip install lief
python -m reverse_lab.cli programa.exe --backend lief --output lief.json
```

### Análisis con Rizin (opcional)

Instala Rizin desde https://github.com/rizinorg/rizin/releases y configura `rz-bin` en tu PATH.

```bash
python -m reverse_lab.cli programa.exe --backend rizin --output rizin.json
```

### Análisis con Ghidra (experimental)

Instala Ghidra desde https://github.com/NationalSecurityAgency/ghidra/releases.

```bash
python -m reverse_lab.cli programa.exe --backend ghidra \
  --ghidra-headless /ruta/a/ghidra/support/analyzeHeadless \
  --export-functions --output funciones.json
```

El flag `--export-functions` solicita exportación de funciones mediante un script Java de Ghidra.
La compatibilidad del lanzador `.bat` de Windows y la exportación con una instalación real de Ghidra aún deben verificarse.

Más información: [instalación en Windows](docs/INSTALL_WINDOWS.md), [Rizin](docs/RIZIN.md), [Ghidra](docs/GHIDRA.md) y [plan de trabajo](docs/ROADMAP.md).

## Límites y seguridad

El proyecto **no incluye ni instala automáticamente** Ghidra, Rizin, Cutter, LIEF o angr. No descompila por sí mismo: delega el análisis avanzado a esos motores externos.

Analiza solo muestras autorizadas. Los analizadores de binarios pueden tener vulnerabilidades; usa entornos aislados para archivos desconocidos. No subas binarios propietarios, credenciales ni muestras confidenciales a este repositorio **público**. Cutter y angr aún no disponen de adaptadores de análisis.

Los resultados JSON son datos no confiables: nunca ejecutes instrucciones o código extraído de una muestra sin revisarlo.
