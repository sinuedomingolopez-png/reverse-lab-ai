# Reverse Lab AI

Laboratorio gratuito y extensible de ingeniería inversa local, con análisis estático y motores opcionales.

## Interfaz visual local (0.4.0)

La aplicación de escritorio permite elegir archivos y motores, consultar el resumen técnico y las funciones exportadas por Ghidra, guardar los informes JSON, **comparar dos informes** y generar una explicación sin IA. Opcionalmente puede pedir una explicación a Ollama en el propio ordenador, con confirmación explícita. No necesita navegador, cuenta, servidor ni pago.

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
- Adaptador Ghidra headless (requiere Ghidra), exportador experimental de nombres y direcciones y exportación **opcional** de pseudocódigo C aproximado (máximo 20 funciones de 8000 caracteres por defecto).
- Diagnóstico local de LIEF, Ghidra, Rizin, Cutter y angr (sin instalarlos).
- Motor de análisis compartido por CLI e interfaz visual local con trabajos en segundo plano.
- Pruebas unitarias sin motores externos y workflow CI.

## Comparación de informes y explicación local

Para comparar dos informes JSON guardados:

```bash
python -m reverse_lab.report_cli compare antes.json despues.json --format text
python -m reverse_lab.report_cli compare antes.json despues.json --output diferencia.json
```

Para una interpretación técnica sin modelo de lenguaje:

```bash
python -m reverse_lab.report_cli explain informe.json
```

Para una explicación generativa **optativa y solo local** instala Ollama y descarga `qwen2.5:3b`:

```bash
ollama pull qwen2.5:3b
python -m reverse_lab.report_cli explain informe.json --ollama
```

El conector envía únicamente metadatos resumidos al servicio local de Ollama, nunca binarios ni código descompilado. No es una conexión con ChatGPT y el modelo puede equivocarse. Ver [guía de comparaciones](docs/COMPARE.md) y [guía de IA local](docs/AI_LOCAL.md).

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
  --export-functions --export-pseudocode --output analisis.json
```

El flag `--export-functions` solicita un listado de funciones. `--export-pseudocode` permite exportar pseudocódigo C aproximado con límites estrictos, solo cuando se solicita. En la interfaz hay una nueva pestaña «Pseudocódigo».
El lanzamiento `.bat` de Windows incorpora protecciones contra caracteres de shell peligrosos y pruebas simuladas; sigue pendiente una ejecución real en Windows. Tampoco se ha validado aún el script Java con una instalación real de Ghidra.

Más información: [instalación en Windows](docs/INSTALL_WINDOWS.md), [Rizin](docs/RIZIN.md), [Ghidra](docs/GHIDRA.md) y [plan de trabajo](docs/ROADMAP.md).

## Límites y seguridad

El proyecto **no incluye ni instala automáticamente** Ghidra, Rizin, Cutter, LIEF o angr. No descompila por sí mismo: delega el análisis avanzado a esos motores externos.

Analiza solo muestras autorizadas. Los analizadores de binarios pueden tener vulnerabilidades; usa entornos aislados para archivos desconocidos. No subas binarios propietarios, credenciales ni muestras confidenciales a este repositorio **público**. Cutter y angr aún no disponen de adaptadores de análisis.

Los resultados JSON son datos no confiables: nunca ejecutes instrucciones o código extraído de una muestra sin revisarlo.
