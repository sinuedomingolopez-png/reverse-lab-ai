"""Build the unsigned Reverse Lab AI portable Windows ZIP using PyInstaller.

The build is performed on Windows. It does not embed third-party analysis
engines or proprietary samples; they are optional separate installations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

APP_NAME = "ReverseLabAI"


def release_version() -> str:
    """Read authoritative package version; never silently ship a stale ZIP."""
    project = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = project.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', text,
                      re.MULTILINE)
    if not match:
        raise RuntimeError("Cannot read semantic release version from pyproject.toml")
    return match.group(1)


def portable_readme() -> str:
    return """REVERSE LAB AI - VERSION PORTABLE DE WINDOWS (__RELEASE__)

1. Extrae el ZIP completo a una carpeta local.
2. Haz doble clic en ReverseLabAI.exe (mantén la carpeta _internal).
3. El analizador basico y la interfaz NO requieren instalar Python.
4. Ghidra, Cutter y Rizin NO estan incluidos; instalalos por separado si los necesitas.
5. El motor LIEF NO esta incluido: para utilizarlo instala la version Python del proyecto.
6. angr NO esta incluido: necesita Python externo con angr instalado.
   Para usar angr desde la version portable, configura REVERSE_LAB_PYTHON
   con la ruta al python.exe que tiene angr instalado.
7. La IA local Ollama NO esta incluida y solo se conecta a localhost si lo autorizas.

ATENCION - EJECUTABLE NO FIRMADO:
Este ZIP de CI NO FIRMADO puede mostrar advertencias de Windows SmartScreen.
Verifica su origen, el SHA-256 publicado y el codigo fuente en GitHub.
No desactives protecciones de Windows para ejecutarlo.

No copies binarios privados, credenciales o archivos sospechosos a una cuenta
en la nube. Para muestras desconocidas usa una maquina virtual aislada.

SI LA APLICACION NO ABRE:
Haz doble clic en DIAGNOSTICO-WINDOWS.cmd dentro de esta carpeta.
Guardara un resumen tecnico sin rutas privadas en la carpeta TEMP de usuario.
No analiza muestras ni envia archivos a Internet.

No es un instalador. No modifica el Registro de Windows ni instala servicios.
""".replace("__RELEASE__", release_version())


def windows_diagnostic_launcher() -> str:
    """Simple opt-in troubleshooting script. Exports only sanitized metadata."""
    return """@echo off
setlocal
cd /d "%~dp0"
set "OUT=%TEMP%\\ReverseLabAI-diagnostico.json"
echo Comprobando Reverse Lab AI sin analizar archivos...
"%~dp0ReverseLabAI.exe" --diagnostics-output "%OUT%"
if errorlevel 1 (
  echo No se pudo generar el diagnostico.
) else (
  echo Diagnostico creado en: "%OUT%"
  echo Contiene solo disponibilidad de motores; no guarda rutas privadas.
)
pause
"""


def build_command(source_root: Path) -> list[str]:
    """Return a fully explicit, reviewable PyInstaller invocation."""
    _ = source_root
    return [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name", APP_NAME,
        "--collect-data", "reverse_lab",
        "--collect-submodules", "reverse_lab",
        "--add-data", "reverse_lab/integrations/angr_worker.py:reverse_lab/integrations",
        "--exclude-module", "angr",
        "--exclude-module", "lief",
        "--paths", ".",
        "--distpath", "dist",
        "--workpath", "build",
        "--specpath", ".",
        "reverse_lab/portable.py",
    ]


def make_archive(
    app_directory: Path, *, version: str | None = None,
) -> tuple[Path, Path]:
    """Create a portable ZIP and separate SHA-256 manifest (not a signature)."""
    if not (app_directory / f"{APP_NAME}.exe").is_file():
        raise ValueError("Portable application EXE is missing; build must succeed first")
    version = version if version is not None else release_version()
    archive = app_directory.parent / f"{APP_NAME}-{version}-windows-x64.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=8) as bundle:
        for file in sorted(app_directory.rglob("*")):
            if file.is_file():
                bundle.write(file, arcname=f"{APP_NAME}/{file.relative_to(app_directory).as_posix()}")
    sha256 = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha256.update(chunk)
    checksum_path = Path(str(archive) + ".sha256")
    checksum_path.write_text(
        f"{sha256.hexdigest()}  {archive.name}\n", encoding="utf-8",
    )
    return archive, checksum_path



def attempt_gui_smoke(
    executable: Path, report_path: Path, *, timeout: int = 12,
) -> dict:
    """Try a GUI smoke test; do not call it passed without a real window.

    GitHub's headless Windows runner may not provide an interactive desktop.
    A timeout is explicitly INCONCLUSIVE, not a successful GUI validation.
    """
    try:
        result = subprocess.run(
            [str(executable), "--gui-smoke-output", str(report_path)],
            check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        status = {
            "status": "not_verified",
            "window_created": False,
            "reason": ("The automated Windows runner did not complete the "
                       "interactive desktop check; manual Windows GUI testing is required."),
        }
        report_path.write_text(
            json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )
        print("WARNING: GUI check timed out in CI; window NOT VERIFIED.")
        return status

    details = (
        report_path.read_text(encoding="utf-8")[:1500] if report_path.is_file()
        else "GUI check did not produce a report."
    )
    if result.returncode != 0 or not report_path.is_file():
        raise RuntimeError(
            f"Portable GUI smoke failed (exit={result.returncode}): {details}"
        )
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("Portable GUI smoke returned invalid JSON") from exc
    if report.get("status") != "passed" or report.get("window_created") is not True:
        raise RuntimeError("Portable GUI smoke did not validate a real window")
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build Reverse Lab AI Windows portable ZIP")
    parser.add_argument("--dry-run", action="store_true", help="Only show build command")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    if args.dry_run:
        print(" ".join(build_command(root)))
        return
    if os.name != "nt":
        parser.error("Building the Windows EXE requires a Windows host")
    subprocess.run(build_command(root), cwd=root, check=True, timeout=1200)

    app = root / "dist" / APP_NAME
    executable = app / f"{APP_NAME}.exe"
    report_path = root / "dist" / "portable-smoke.json"
    completed = subprocess.run(
        [str(executable), "--self-test-output", str(report_path)],
        cwd=root, check=False, timeout=50,
    )
    if completed.returncode != 0 or not report_path.is_file():
        details = report_path.read_text(encoding="utf-8")[:1500] if report_path.is_file() \
                  else "No JSON report produced (possibly a frozen import/startup error)."
        raise RuntimeError(
            f"Portable EXE startup self-test failed (exit={completed.returncode}): {details}"
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("status") != "ready" or report.get("frozen") is not True:
        raise RuntimeError("Portable Windows bundle does not include the required scripts")

    support_path = root / "dist" / "support-smoke.json"
    support_process = subprocess.run(
        [str(executable), "--diagnostics-output", str(support_path)],
        cwd=root, check=False, timeout=30,
    )
    if support_process.returncode != 0 or not support_path.is_file():
        raise RuntimeError("Portable EXE could not create a privacy-safe support report")
    support = json.loads(support_path.read_text(encoding="utf-8"))
    if (support.get("schema") != "reverse-lab-support-v1"
            or support.get("portable") is not True
            or support.get("bundle", {}).get("status") != "ready"):
        raise RuntimeError("Portable EXE failed its offline support diagnostics")


    gui_smoke_path = root / "dist" / "gui-smoke.json"
    gui_report = attempt_gui_smoke(executable, gui_smoke_path)
    if gui_report["status"] == "not_verified":
        print("The ZIP is built, but real Windows GUI usage still needs a manual check.")

    (app / "DIAGNOSTICO-WINDOWS.cmd").write_text(
        windows_diagnostic_launcher(), encoding="utf-8",
    )
    (app / "LEEME-PORTABLE.txt").write_text(portable_readme(), encoding="utf-8")
    archive, checksum = make_archive(app)
    print(f"Portable ZIP: {archive}")
    print(f"SHA256 file: {checksum}")
    print("Bundle integrity: OK. Windows GUI verification: " + gui_report["status"])


if __name__ == "__main__":
    main()
