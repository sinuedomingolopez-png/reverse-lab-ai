# Pruebas de motores reales — Reverse Lab AI 0.12

Hasta la versión 0.11, las pruebas automáticas usaban mayoritariamente motores simulados. Reverse Lab AI 0.12 añade una comprobación de integración que instala y **utiliza los motores auténticos** para analizar un ELF x86-64 diminuto generado por el propio laboratorio, sin ejecutarlo ni utilizar archivos personales.

## LIEF (Windows y Linux)

LIEF interpreta metadatos ELF, PE y Mach-O. La prueba de integración verifica que la versión realmente instalada reconoce nuestra muestra ELF y recupera su dirección de entrada exacta (`0x401000`). El informe muestra `passed`, `failed` o `missing`.

Instalación opcional:

```powershell
py -m pip install lief
py -m reverse_lab.engine_probe --engine lief --output lief-test.json
```

## angr (Linux en la CI)

angr permite recuperar información de flujo de control mediante `CFGFast`. La prueba invoca **el mismo proceso worker real** que utiliza Reverse Lab AI para analizar archivos, y verifica que aparecen funciones y nodos del CFG. No realiza `CFGEmulated`, simulación de estados ni ejecución simbólica.

```powershell
py -m pip install angr
py -m reverse_lab.engine_probe --engine angr --timeout 120 --output angr-test.json
```

La instalación puede ser pesada. En el ZIP portable, angr sigue requiriendo un Python externo con angr instalado y la configuración de `REVERSE_LAB_PYTHON`. Esta prueba está disponible al usar la versión Python del proyecto.

## Desde la interfaz

Abre `python -m reverse_lab.gui` o `ReverseLabAI.exe`, pulsa **Probar LIEF/angr**, selecciona el motor y ejecuta la autoprueba. El laboratorio muestra comprobaciones de disponibilidad y resultados, sin guardar nada automáticamente.

**Advertencia para el ZIP portable:** LIEF no viene incluido; incluso si instalas LIEF en otro Python, el EXE base no puede importarlo automáticamente. Para utilizar LIEF debes abrir el proyecto mediante ese Python instalado. La aplicación portable puede seguir identificando el motor como ausente.

## GitHub Actions: motores auténticos

El flujo principal `Tests` mantiene sus cuatro combinaciones estables de Windows/Linux y Python 3.10/3.13, usando principalmente dobles de prueba de los motores externos. Las comprobaciones con LIEF y angr **instalados de verdad** se encuentran en el flujo independiente `Real analysis engines`, disponible para ejecución manual en GitHub Actions (`workflow_dispatch`). **No están verificadas automáticamente en esta versión**: hasta disponer de una ejecución confirmada no se deben presentar como superadas.


El nuevo flujo [Real analysis engines](https://github.com/sinuedomingolopez-png/reverse-lab-ai/actions/workflows/real-engines.yml) instala LIEF de PyPI en Windows y Linux, y angr de PyPI en Linux con Python 3.11. Ejecuta `reverse_lab.engine_probe` y publica informes JSON con los resultados técnicos. No utiliza binarios desconocidos, contraseñas ni datos personales.

Un resultado `passed` confirma solo que la integración concreta pudo analizar correctamente esta muestra. **No garantiza seguridad ni precisión general** al procesar programas reales. LIEF interpreta archivos en el proceso Python y angr en un proceso hijo con límite de tiempo, pero ninguno ofrece aislamiento de seguridad equivalente a una VM.

## Próximos pasos

Siguen pendientes las integraciones reales de **Rizin, Cutter y Ghidra**, y la prueba del ZIP en un ordenador Windows físico con esas herramientas instaladas. La autoprueba de Ghidra existente se puede ejecutar localmente con `python -m reverse_lab.ghidra_probe`.

Documentación oficial: [LIEF](https://lief.re/doc/latest/) y [angr CFGFast](https://api.angr.io/en/latest/analyses/cfg.html).
