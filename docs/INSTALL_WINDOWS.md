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

## Ghidra (experimental)

Instala Ghidra desde https://github.com/NationalSecurityAgency/ghidra/releases. El adaptador headless requiere señalar `support/analyzeHeadless.bat`.

**Importante:** la invocación de archivos `.bat` en Windows todavía no se ha verificado en un equipo Windows real, por lo que puede requerir ajustes. No ejecutes análisis de archivos no fiables fuera de una máquina virtual.

## Limitaciones

- Los motores profesionales no se descargan ni instalan automáticamente.
- Cutter y angr siguen pendientes de integración.
- No se ejecuta el binario que se examina: se hacen análisis estáticos. Los analizadores pueden contener vulnerabilidades; usa muestras autorizadas y entornos aislados.
