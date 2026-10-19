# Motores reales — Reverse Lab AI 0.13

Las comprobaciones locales de Windows usan instalaciones auténticas y muestras sintéticas generadas por el proyecto. No ejecutan los programas analizados. Un resultado válido acredita estas muestras y versiones concretas, no cualquier binario.

| Motor | Instalación probada | Evidencia local |
|---|---|---|
| LIEF | 1.0.0, Python 3.11 | ELF, PE y Mach-O reconocidos; PE con importación ExitProcess, biblioteca KERNEL32.dll y exportación synthetic_helper |
| Rizin | 0.9.1, Windows x64 | Secciones, símbolos y dos funciones del ELF sintético mediante rz-bin y rizin |
| Ghidra | 12.1.4, JDK Temurin 25.0.4.1+1 | Dos funciones, dos pseudocódigos no vacíos y una llamada; scripts Java ejecutados por headless; consulta mediante cliente MCP oficial |
| angr | 10.0.4.post1, Python 3.12.14 | CFGFast en worker separado; tres funciones, cuatro nodos y tres aristas |
| Cutter | 2.5.0, Windows x64 | Detección y apertura del proceso con el ELF sintético; navegación manual y sincronización bidireccional no verificadas |

## Instalar y comprobar

La aplicación base admite Python 3.10+. MCP necesita 3.11+. angr actual necesita 3.12+, por lo que se recomienda Python 3.12 para un entorno conjunto:

```powershell
python -m pip install ".[mcp,desktop,validation]"
python -m reverse_lab.engine_probe --engine lief --output lief-test.json
python -m reverse_lab.engine_probe --engine angr --timeout 120 --output angr-test.json
python -m reverse_lab.ghidra_probe
python -m unittest discover -s integration_tests -v
```

Ghidra y su JDK, Rizin y Cutter se instalan externamente. Configura GHIDRA_HOME, JAVA_HOME y PATH según las guías específicas. Para usar otro entorno de angr, define REVERSE_LAB_PYTHON con la ruta absoluta a su python.exe. Funciona desde la aplicación fuente y desde el portable. No habilita ejecución simbólica.

El ZIP base no incluye LIEF ni angr. Para LIEF abre la aplicación desde un Python que lo tenga instalado. El agente MCP también se ejecuta desde Python externo. La ausencia de motores opcionales no impide usar el análisis básico.

## CI y alcance

Los workflows `Real analysis engines` y `Real MCP protocol and permissions` instalan motores reales, con trabajos separados de las pruebas con dobles. El segundo descarga Ghidra y Rizin oficiales con SHA-256 fijado y comprueba el recorrido MCP a Ghidra en Windows. Las pruebas condicionadas ausentes aparecen como omitidas; no deben interpretarse como integraciones superadas. Consulta la ejecución del commit concreto en GitHub Actions.

Los trabajos MCP tienen tiempo, tamaño, concurrencia y memoria limitados. En Windows utilizan Job Objects para el árbol de procesos. Estos controles no equivalen a una VM ni garantizan aislamiento de red o de vulnerabilidades de los motores. Las invocaciones directas fuera del agente conservan sus propios límites. Consulta [validación](VALIDATION_0_13.md) y [MCP](MCP_CHATGPT.md).

Fuentes oficiales: [LIEF](https://lief.re/doc/latest/), [angr](https://docs.angr.io/), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Rizin](https://github.com/rizinorg/rizin), [Cutter](https://github.com/rizinorg/cutter).
