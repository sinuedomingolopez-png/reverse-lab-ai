# Reverse Lab AI

Laboratorio gratuito y extensible de ingeniería inversa local, con análisis estático y motores opcionales.

## Interfaz visual local (0.12.0)

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
- **Cutter externo**: abrir el archivo seleccionado en Cutter mediante un botón, con confirmación explícita (requiere instalar Cutter).
- **angr CFGFast**: analizar funciones, nodos y conexiones del CFG en un proceso separado, sin cargar dependencias compartidas (requiere instalar angr).
- Adaptador Ghidra headless (requiere Ghidra), exportador experimental de nombres/direcciones, pseudocódigo C aproximado y **mapa estático de llamadas entre funciones**.
- Diagnóstico local de LIEF, Ghidra, Rizin, Cutter y angr (sin instalarlos), y autoprueba opcional de Ghidra sobre un ELF sintético.
- Motor de análisis compartido por CLI e interfaz visual local con trabajos en segundo plano.
- **Explorador unificado de funciones:** búsqueda por nombre/dirección, pseudocódigo, referencias entrantes y salientes, navegación entre funciones y carga de JSON existentes.
- Pruebas unitarias sin motores externos y workflow CI.
- Empaquetado Windows portable (PyInstaller onedir), test de integridad, diagnóstico sin interfaz, comprobación gráfica cuando hay escritorio interactivo, y manifiesto SHA-256.

## Comprobación de motores auténticos (0.12)

Se ha preparado un flujo de integración para comprobar **LIEF real** sobre Windows/Linux y **angr real** sobre Linux, analizando únicamente un ELF sintético que el programa genera y no ejecuta. **Estas pruebas con motores instalados aún no tienen una ejecución verificada**; se pueden lanzar manualmente desde GitHub Actions → Real analysis engines. La autoprueba distingue motor ausente, error y resultado válido. Permite detectar incompatibilidades que no aparecían al utilizar simuladores.

```bash
python -m pip install lief
python -m reverse_lab.engine_probe --engine lief
python -m pip install angr
python -m reverse_lab.engine_probe --engine angr --timeout 120
```

En la interfaz, pulsa **Probar LIEF/angr**. Las dependencias siguen siendo opcionales; el ZIP base no las incluye. Consulta [la guía de validación de motores reales](docs/REAL_ENGINES.md).

## Diagnóstico privado y soporte para Windows (0.11)

La ventana principal incorpora **Guardar diagnóstico**, que exporta un resumen local **sin rutas, nombres de usuario, binarios ni pseudocódigo** y solo cuando tú lo decides. Si el EXE no abre, en la carpeta portable puedes ejecutar `DIAGNOSTICO-WINDOWS.cmd` para generar ese mismo informe sin iniciar la ventana.

La autoprueba gráfica ahora construye una ventana Tkinter directamente, sin sustituir internamente su bucle de eventos. GitHub Actions intenta comprobar el EXE en Windows, pero si el runner no tiene escritorio interactivo registra `not_verified`; el ZIP solo se publica tras superar su prueba de integridad y el diagnóstico sin interfaz.

Consulta la [guía de soporte Windows](docs/SUPPORT_WINDOWS.md).

## Historial privado de análisis (0.10)

Puedes conservar informes y recuperarlos cuando los necesites. El historial es **optativo**: utiliza **Guardar en historial**, revisa la advertencia sobre pseudocódigo y confirma. No guarda nada automáticamente. Con **Historial local** podrás volver a abrir informes o eliminar copias, sin repetir el análisis.

Las copias se guardan en una carpeta privada de usuario (Windows: `%LOCALAPPDATA%\ReverseLabAI\history`), con un máximo de 30 informes y 4 MiB por copia. No se envían a GitHub, Ollama ni otros servicios. **No están cifradas**; evita guardar material confidencial en ordenadores compartidos.

Consulta [historial local, límites y privacidad](docs/HISTORY_LOCAL.md).

## Windows portable sin instalar Python (0.11)

La compilación opcional de Windows usa PyInstaller y genera un ZIP con `ReverseLabAI.exe`. Permite abrir la interfaz y realizar análisis básicos **sin instalar Python**. El ZIP se produce en GitHub Actions después de ejecutar pruebas, comprobar los scripts de Ghidra e **intentar crear una ventana Tkinter real en Windows**. Si el runner de GitHub no dispone de un escritorio interactivo, el resultado queda como `not_verified` (no como éxito). La ventana sí tiene pruebas reales con pantalla virtual Linux.

Descarga las compilaciones desde [Actions → Windows portable](https://github.com/sinuedomingolopez-png/reverse-lab-ai/actions/workflows/windows-portable.yml). El artefacto de CI dura 14 días, puede requerir inicio de sesión y **no está firmado digitalmente**. No desactives SmartScreen; verifica procedencia y SHA-256. Ghidra, Cutter, Rizin, LIEF y angr siguen siendo opcionales y NO están incluidos. Para usar angr desde el portable necesitas un Python externo con angr instalado.

Ver [guía completa de descarga, uso y verificación](docs/WINDOWS_PORTABLE.md).

## Explorador unificado (0.6)

En la pestaña **Funciones**, pulsa **Explorar funciones** para abrir el navegador de funciones con búsqueda y fichas vinculadas al pseudocódigo y a las llamadas. Haz doble clic en una función, o en una relación de **Mapa de llamadas**, para abrir su ficha.

También puedes seleccionar **Abrir informe JSON** para explorar análisis ya guardados, sin repetir el procesamiento. El navegador trabaja localmente y no comparte pseudocódigo con modelos de IA. Consulta la [guía del explorador](docs/FUNCTION_EXPLORER.md).

## Cutter y angr (0.8)

La aplicación ofrece **Abrir archivo en Cutter** para enviar una muestra autorizada al editor gráfico Cutter ya instalado, sin incrustarlo ni instalarlo.

Para el análisis de flujo estático `CFGFast` de angr (sin ejecutar el programa objetivo), instala la dependencia opcional y analiza:

```bash
python -m pip install angr
python -m reverse_lab.cli ejemplo.bin --backend angr --timeout 90 --output informe-angr.json
```

También puedes elegir `angr` desde la interfaz. Requiere una instalación local propia y tiene límite de 32 MiB para la muestra, 600 segundos para el proceso y 300 funciones exportadas por defecto. No es una máquina virtual ni un sandbox seguro: los programas desconocidos deben analizarse en un entorno aislado.

Instrucciones y límites: [Cutter y angr](docs/CUTTER_ANGR.md).

## Autoprueba real de Ghidra (0.7)

Puedes comprobar una instalación de Ghidra con una muestra ELF x86-64 sintética creada por el propio laboratorio. **No se ejecuta la muestra** ni se envía a internet:

```bash
python -m reverse_lab.ghidra_probe --check-only
python -m reverse_lab.ghidra_probe --ghidra-headless /ruta/a/ghidra/support/analyzeHeadless --output diagnostico-ghidra.json
```

En la interfaz, pulsa **Autoprueba Ghidra** junto a la ruta del lanzador, y elige **Solo detectar** o **Ejecutar autoprueba completa**. Se validan las exportaciones de funciones, pseudocódigo y llamadas. El diagnóstico distingue ausencia de herramienta, detección sin ejecución, éxito y fallo.

**Importante:** Ghidra debe estar realmente instalado y tener un JDK compatible. Estas pruebas no se han ejecutado aún contra una instalación real de Ghidra desde este proyecto. Consulta la [guía detallada para Windows](docs/GHIDRA_SELFTEST.md).

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
  --export-functions --export-pseudocode --export-call-graph --output analisis.json
```

El flag `--export-call-graph` solicita un conjunto acotado de llamadas estáticas entre funciones, consultable en la nueva pestaña **Mapa de llamadas** y exportable a formato Graphviz DOT. Consulta [la guía del mapa de llamadas](docs/CALL_GRAPH.md).

El flag `--export-functions` solicita un listado de funciones. `--export-pseudocode` permite exportar pseudocódigo C aproximado con límites estrictos, solo cuando se solicita. En la interfaz hay una nueva pestaña «Pseudocódigo».
El lanzamiento `.bat` de Windows incorpora protecciones contra caracteres de shell peligrosos y pruebas simuladas; sigue pendiente una ejecución real en Windows. Tampoco se ha validado aún el script Java con una instalación real de Ghidra.

Más información: [instalación en Windows](docs/INSTALL_WINDOWS.md), [Rizin](docs/RIZIN.md), [Ghidra](docs/GHIDRA.md) y [plan de trabajo](docs/ROADMAP.md).

## Límites y seguridad

El proyecto **no incluye ni instala automáticamente** Ghidra, Rizin, Cutter, LIEF o angr. No descompila por sí mismo: delega el análisis avanzado a esos motores externos.

Analiza solo muestras autorizadas. Los analizadores de binarios pueden tener vulnerabilidades; usa entornos aislados para archivos desconocidos. No subas binarios propietarios, credenciales ni muestras confidenciales a este repositorio **público**. Cutter se abre como aplicación externa; angr aporta `CFGFast` estático. No existe una integración de depuración o ejecución simbólica, ni una conexión remota con ChatGPT.

Los resultados JSON son datos no confiables: nunca ejecutes instrucciones o código extraído de una muestra sin revisarlo.
