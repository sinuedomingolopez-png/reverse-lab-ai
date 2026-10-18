"""Build the unsigned Reverse Lab AI portable Windows ZIP using PyInstaller.

The build is performed on Windows. It does not embed third-party analysis
engines or proprietary samples; they are optional separate installations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

APP_NAME = "ReverseLabAI"


def portable_readme() -> str:
    return """REVERSE LAB AI - VERSION PORTABLE DE WINDOWS (0.9.0)

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

No es un instalador. No modifica el Registro de Windows ni instala servicios.
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
    app_directory: Path, *, version: str = "0.9.0",
) -> tuple[Path, Path]:
    """Create a portable ZIP and separate SHA-256 manifest (not a signature)."""
    if not (app_directory / f"{APP_NAME}.exe").is_file():
        raise ValueError("Portable application EXE is missing; build must succeed first")
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

    (app / "LEEME-PORTABLE.txt").write_text(portable_readme(), encoding="utf-8")
    archive, checksum = make_archive(app)
    print(f"Portable ZIP: {archive}")
    print(f"SHA256 file: {checksum}")
    print("Smoke-test: OK (only local bundle integrity, not Ghidra/Cutter/angr)")


if __name__ == "__main__":
    main()
