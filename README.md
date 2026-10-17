# Reverse Lab AI

Laboratorio de ingeniería inversa local, gratuito y extensible.

## Funciones actuales
- Identificación básica de ejecutables PE, ELF, Mach-O y WebAssembly, y archivos ZIP.
- Cálculo SHA-256 y tamaño.
- Informe JSON generado sin ejecutar el binario.
- Pruebas unitarias y CI.

## Inicio (Python 3.10+)
```bash
python -m unittest discover -s tests -v
python -m reverse_lab.cli ruta/al/archivo --output informe.json
```

No se ejecutan los archivos analizados. Utiliza únicamente software que estés autorizado a investigar.

## Integraciones previstas
1. LIEF: análisis estructural de binarios.
2. Ghidra: descompilación y automatización local.
3. Rizin: análisis adicional por CLI.
4. Cutter: interfaz de escritorio opcional, no se incrusta inicialmente.
5. angr: ejecución simbólica opcional.

Las integraciones aún **no están instaladas ni operativas**: se incorporarán mediante adaptadores, pruebas y revisión de licencias. No almacenamos ejecutables de terceros en el repositorio.
