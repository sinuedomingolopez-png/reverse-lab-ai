# Cutter y angr — Reverse Lab AI 0.8

Dos integraciones nuevas **opcionales y locales**. Ninguna instala software automáticamente.

## Cutter: abrir un ejecutable en una ventana profesional

Cutter es una aplicación gráfica de ingeniería inversa basada en Rizin. Se descarga por separado desde el repositorio oficial: https://github.com/rizinorg/cutter/releases

1. Instala/descomprime Cutter en tu ordenador, siguiendo las instrucciones oficiales.
2. Abre Reverse Lab AI: `python -m reverse_lab.gui`.
3. Selecciona un archivo que estés autorizado a analizar.
4. Pulsa **Abrir archivo en Cutter** y confirma. Se abrirá una aplicación independiente con ese archivo. Reverse Lab AI no lo ejecuta.

Si no encuentra Cutter, define una variable de entorno `CUTTER_PATH` con la ruta completa a su ejecutable.

Ejemplo en PowerShell, adaptando la ruta real:

```powershell
$env:CUTTER_PATH="C:\Herramientas\Cutter\Cutter.exe"
py -m reverse_lab.gui
```

La integración utiliza el argumento de archivo documentado por Cutter, sin `shell=True`; **no incluye Cutter en el paquete**, no ejecuta scripts ni activa el modo escritura. Cutter y sus complementos son aplicaciones de terceros; para muestras desconocidas utiliza un entorno aislado y un perfil sin privilegios.

Referencia oficial: https://cutter.re/docs/user-docs/command-line.html

## angr: análisis de flujo estático con CFGFast

angr es un entorno abierto de análisis binario. La integración actual utiliza **CFGFast**, el análisis estático que busca funciones y bloques de código. No incorpora `CFGEmulated`, ejecución simbólica, depuración ni reconstrucción de código fuente.

Para instalarlo de forma opcional en el mismo Python que ejecuta Reverse Lab AI:

```powershell
py -m pip install angr
```

Para iniciar un análisis por terminal:

```powershell
py -m reverse_lab.cli "C:\muestras\mi_programa.exe" --backend angr --timeout 90 --output informe-angr.json
```

O desde la interfaz: elige **angr**, selecciona el archivo y pulsa **Analizar archivo**. El informe incluye SHA-256 y formato básico, funciones con nombre y dirección si han sido recuperadas, número de nodos y enlaces del CFG y un indicador de resultados truncados.

La lista se puede explorar desde **Funciones → Explorar funciones**, junto con los demás informes JSON. No aporta automáticamente el pseudocódigo o el grafo de llamadas de Ghidra.

### Límites del adaptador

- Tamaño máximo del archivo: **32 MiB**.
- Tiempo máximo de análisis del proceso angr: **600 s** (por defecto la interfaz usa 180 s y el adaptador independiente 60 s).
- Hasta **300 funciones** por defecto; el adaptador admite un máximo de 500.
- JSON de salida limitado a **2 MiB** y validado.
- El worker se ejecuta como un **proceso Python separado**, sin shell y con bibliotecas compartidas desactivadas (`auto_load_libs=False`).

**Importante:** una limitación de tiempo no equivale a un aislamiento seguro de memoria, sistema de archivos o red. angr es software complejo y puede sufrir fallos al interpretar archivos hostiles. Para muestras no fiables se recomienda una VM aislada, con permisos limitados y sin datos privados. Tampoco hay garantía de recuperar todas las funciones.

Documentación oficial: https://api.angr.io/en/latest/analyses/cfg.html

## Estado de verificación

Las pruebas automáticas utilizan respuestas simuladas de angr y una prueba de proceso real con un módulo de angr falso, **no una instalación real**. El lanzamiento de Cutter está probado mediante un proceso simulado. Para validar las herramientas instaladas, hay que ejecutarlas en un equipo con Cutter/angr configurados.

El software permanece separado de Veneno Azul y no comparte archivos automáticamente.
