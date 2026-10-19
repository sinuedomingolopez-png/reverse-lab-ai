# Reverse Lab AI 0.9 — versión portable para Windows

La versión portable se compila **en GitHub Actions sobre Windows** usando PyInstaller en modo `--onedir --windowed`. Se crea un ZIP que contiene una carpeta `ReverseLabAI`, su ejecutable `ReverseLabAI.exe`, los archivos de soporte y una guía `LEEME-PORTABLE.txt`.

## Descargar y abrir

1. Abre el repositorio y entra en **Actions → Windows portable**:
   https://github.com/sinuedomingolopez-png/reverse-lab-ai/actions/workflows/windows-portable.yml
2. Abre una ejecución que indique **Success**.
3. En **Artifacts**, descarga `ReverseLabAI-0.13.0-windows-x64`. GitHub puede pedir inicio de sesión y los archivos pueden caducar a los 14 días.
4. Extrae los archivos del artifact y, a continuación, descomprime `ReverseLabAI-0.13.0-windows-x64.zip`. Conserva completa la carpeta `ReverseLabAI`, especialmente `_internal`.
5. Haz doble clic en **ReverseLabAI.exe** dentro de la carpeta. El análisis básico, el historial local y la interfaz no necesitan Python instalado.

**El ejecutable todavía no está firmado**. Windows puede mostrar una advertencia de SmartScreen: no desactives las protecciones del sistema. Verifica la procedencia del workflow de GitHub, el código fuente, el archivo de checksum y, si tienes dudas, utiliza la versión Python original.

## Verificar el ZIP con SHA-256

Junto al ZIP hay un archivo `.zip.sha256` con el hash esperado. En PowerShell, dentro de la carpeta de descargas:

```powershell
Get-FileHash .\ReverseLabAI-0.13.0-windows-x64.zip -Algorithm SHA256
Get-Content .\ReverseLabAI-0.13.0-windows-x64.zip.sha256
```

Los dos hashes deben coincidir. El hash detecta cambios accidentales o alteraciones respecto al manifest, **pero no garantiza por sí mismo la identidad del autor**.

## ¿Qué funciona sin Python adicional?

- Interfaz gráfica, análisis básico, SHA-256, resumen de tipos y exportación JSON.
- Apertura y comparación de informes JSON, explorador de funciones y mapa de llamadas guardado.
- Ollama solo si está instalado en este ordenador y se autoriza la conexión a `localhost`.
- Ghidra, Rizin y Cutter **solo** si están instalados por separado. El ZIP portable incluye los scripts de exportación de Ghidra, pero no Ghidra ni Java.

## ¿Qué necesita Python externo?

**angr** requiere su propia instalación Python, y su motor no viene en el ZIP portable.

En PowerShell, con una instalación de Python que tenga angr:

```powershell
py -m pip install angr
$env:REVERSE_LAB_PYTHON="C:\ruta\al\python.exe"
.\ReverseLabAI\ReverseLabAI.exe
```

Sustituye la ruta de ejemplo por el `python.exe` donde instalaste angr. El ZIP incluye el script `angr_worker.py` para que ese intérprete pueda ejecutar la tarea sin instalar el paquete Reverse Lab AI.

**LIEF** tampoco se incluye en esta compilación básica: para utilizarlo instala la versión Python del proyecto y `pip install lief`.

## Qué comprueba el CI

1. Ejecuta las pruebas de Python sobre Windows.
2. Construye la carpeta portable con PyInstaller.
3. Ejecuta el `.exe` compilado con `--self-test-output` (sin mostrar ventanas ni analizar muestras), y después con `--gui-smoke-output` para intentar comprobar que crea una ventana real y sus controles sin procesar binarios. En un runner Windows sin escritorio interactivo puede quedar como `not_verified`; esto **no es una prueba superada** de la ventana.
4. Comprueba que están los tres scripts Java de Ghidra, el estado `frozen` y la generación de un informe de soporte sin datos privados (sin abrir la interfaz).
5. Crea el ZIP, calcula su SHA-256 y comprueba el manifiesto, la salida del diagnóstico y el estado explícito de la comprobación gráfica antes de subir el artifact.

**Un runner Windows de GitHub puede no disponer de un escritorio interactivo: si el test se bloquea, el estado será `not_verified`. Abrir la ventana en Linux virtual o superar pruebas de Python no equivale a probarla en un ordenador físico Windows** ni demuestra que Cutter, Rizin, Ghidra o angr reales funcionen en el equipo del usuario. Su integración debe probarse localmente.

## Compilar por tu cuenta

En Windows con Python y PyInstaller instalados:

```powershell
py -m pip install "pyinstaller==6.22.3" "tkinterdnd2==0.6.4"
py tools\build_windows.py
```

Obtendrás `dist/ReverseLabAI-0.13.0-windows-x64.zip`, su manifiesto SHA-256 y `dist/portable-smoke.json`.

## Seguridad y costes

- Portable gratuito. No requiere cuenta en un servicio de pago ni instalador con permisos elevados.
- **Sin firma digital** y sin garantía de funcionamiento con versiones futuras de Windows.
- No incorpora aislación de memoria, sistema de archivos o red; para analizar muestras desconocidas utiliza una máquina virtual desconectada y sin archivos privados.
- No envíes binarios, pseudocódigo o informes confidenciales a servidores remotos.
- La publicación automática del ZIP se realiza como artifact temporal, no como release firmado.

Documentación de PyInstaller: https://pyinstaller.org/en/stable/operating-mode.html
