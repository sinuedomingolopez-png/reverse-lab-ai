# Reverse Lab AI: instalación local en Windows

Necesitas Python 3.10 o posterior y Git.

Abre PowerShell:

```powershell
git clone https://github.com/sinuedomingolopez-png/reverse-lab-ai.git
cd reverse-lab-ai
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m reverse_lab.doctor
```

## Abrir la interfaz visual

Desde PowerShell:

```powershell
.\.venv\Scripts\python.exe -m reverse_lab.gui
```

O haz doble clic en `start-reverse-lab.bat`, que utilizará el Python del entorno `.venv` cuando exista. Sin dependencias adicionales para el modo básico. Consulta [la guía de la interfaz](GUI.md).

### Explorar informes guardados

En la ventana, abre **Funciones → Abrir informe JSON** para cargar un resultado previamente generado, y pulsa **Explorar funciones**. También puedes hacer doble clic en una función o una relación para abrir su ficha; consulta [la guía del explorador](FUNCTION_EXPLORER.md).

## Analizador básico (sin dependencias de terceros)

```powershell
.\.venv\Scripts\python.exe -m reverse_lab.cli .\README.md --output resumen.json
```

## LIEF (opcional)

```powershell
.\.venv\Scripts\python.exe -m pip install lief
.\.venv\Scripts\python.exe -m reverse_lab.cli "C:\ruta\programa.exe" --backend lief --output lief.json
```

## Rizin (opcional)

Instala Rizin desde https://github.com/rizinorg/rizin/releases y verifica que `rz-bin` está en el PATH:

```powershell
rz-bin -h
.\.venv\Scripts\python.exe -m reverse_lab.cli "C:\ruta\programa.exe" --backend rizin --output rizin.json
```

Si no se encuentra `rz-bin`, puedes pasar `--rizin-executable` con la ruta completa al ejecutable.

## Autoprueba de Ghidra (0.7)

Después de instalar Ghidra, abre la interfaz y pulsa **Autoprueba Ghidra**. Alternativamente, ejecuta en PowerShell:

```powershell
.\.venv\Scripts\python.exe -m reverse_lab.ghidra_probe --ghidra-headless "C:\Herramientas\ghidra\support\analyzeHeadless.bat" --output diagnostico-ghidra.json
```

Sustituye la ruta de ejemplo por la real. Si Ghidra no está instalado, verás el estado `missing`; no se descarga ni se instala automáticamente. Consulta [GHIDRA_SELFTEST.md](GHIDRA_SELFTEST.md).

## Cutter y angr (opcionales)

Para usar Cutter, instálalo desde [releases oficiales](https://github.com/rizinorg/cutter/releases); abre Reverse Lab AI, selecciona tu archivo y pulsa **Abrir archivo en Cutter**. Si no se encuentra el lanzador, define `CUTTER_PATH`.

Para activar angr CFGFast:

```powershell
.\.venv\Scripts\python.exe -m pip install angr
.\.venv\Scripts\python.exe -m reverse_lab.cli ".\archivo_autorizado.exe" --backend angr --timeout 90 --output resultado-angr.json
```

También puedes seleccionar `angr` en la interfaz. Es un análisis estático opcional, no un aislamiento de seguridad. Consulta [CUTTER_ANGR.md](CUTTER_ANGR.md).

## Ghidra (experimental)

Instala Ghidra desde https://github.com/NationalSecurityAgency/ghidra/releases. El adaptador headless requiere señalar `support/analyzeHeadless.bat`.

**Importante:** la invocación de archivos `.bat` en Windows todavía no se ha verificado en un equipo Windows real, por lo que puede requerir ajustes. No ejecutes análisis de archivos no fiables fuera de una máquina virtual.

## Limitaciones

- Los motores profesionales no se descargan ni instalan automáticamente.
- Cutter se abre como aplicación separada; angr CFGFast requiere una instalación opcional. No hay integración de ejecución simbólica.
- No se ejecuta el binario que se examina: se hacen análisis estáticos. Los analizadores pueden contener vulnerabilidades; usa muestras autorizadas y entornos aislados.
