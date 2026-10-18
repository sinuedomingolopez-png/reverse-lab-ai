# Autoprueba real de Ghidra — Reverse Lab AI 0.7

Esta funcionalidad comprueba **una instalación local real de Ghidra**, cuando está disponible. Crea un ELF x86-64 mínimo en una carpeta temporal, le pide a Ghidra que lo analice y verifica la exportación de funciones, pseudocódigo C aproximado y llamadas estáticas. El archivo ELF **no se ejecuta**, ni se descarga de internet ni se sube a servidores.

## Requisitos

- Python 3.10 o posterior y Reverse Lab AI 0.7 instalado o clonado.
- Una instalación oficial de Ghidra. Descarga únicamente la distribución adecuada desde: https://github.com/NationalSecurityAgency/ghidra/releases
- Un JDK compatible con **la versión concreta de Ghidra**: consulta sus instrucciones de instalación. La documentación actual de Ghidra indica JDK 25 para las versiones recientes; no supongas que cualquier Java existente sirve.
- Sin modelo de IA, servicios de pago ni conexión a ChatGPT.

## Desde Windows (PowerShell)

Para ver si Ghidra está detectado:

```powershell
py -m reverse_lab.ghidra_probe --check-only
```

Si no aparece, indica dónde está el lanzador:

```powershell
py -m reverse_lab.ghidra_probe --ghidra-headless "C:\Herramientas\ghidra\support\analyzeHeadless.bat" --check-only
```

Para **ejecutar una prueba completa** con el Ghidra instalado:

```powershell
py -m reverse_lab.ghidra_probe --ghidra-headless "C:\Herramientas\ghidra\support\analyzeHeadless.bat" --output diagnostico-ghidra.json
```

Sustituye la ruta por la de tu instalación. Si has instalado el paquete, puedes usar `reverse-lab-ghidra-check` en vez de `py -m reverse_lab.ghidra_probe`.

También puedes establecer `GHIDRA_HOME` en la sesión actual:

```powershell
$env:GHIDRA_HOME="C:\Herramientas\ghidra"
py -m reverse_lab.ghidra_probe
```

## Desde la interfaz

1. Abre Reverse Lab AI y pulsa **Autoprueba Ghidra**, situado junto a la configuración del lanzador.
2. Introduce la ruta a `analyzeHeadless` si la detección automática no lo encuentra.
3. **Solo detectar** verifica que existe el lanzador, pero no prueba si Ghidra funciona.
4. **Ejecutar autoprueba completa** abre un proceso local de Ghidra con la muestra sintética y muestra un informe detallado. La interfaz seguirá respondiendo.

## Qué comprueba

1. Que se localiza el lanzador `analyzeHeadless`.
2. Que Reverse Lab AI genera una muestra ELF64 reconocible con dos bloques de código x86-64.
3. Que Ghidra procesa esa muestra mediante su analizador headless.
4. Que los tres scripts Java generan archivos JSON válidos (funciones, pseudocódigo, mapa de llamadas).
5. Que los recuentos de los tres archivos coinciden con sus listas exportadas.

**Estados:**
- `missing`: Ghidra no se detecta. No se ejecutó nada.
- `available`: se detecta un lanzador, pero solo se ha solicitado `--check-only`. No implica que funcione.
- `passed`: se completó el proceso de Ghidra y se validaron los JSON.
- `failed`: alguna fase falló. El resultado incluirá diagnóstico acotado.

Las listas vacías generan advertencias porque la detección real depende de la configuración, versión y opciones de Ghidra; no se presentan como evidencia de llamadas o de comportamiento.

## Limitaciones y seguridad

- La **CI estándar** sigue utilizando simuladores; **no instala ni ejecuta Ghidra real**. Esta prueba necesita que Ghidra esté instalado en el equipo donde se ejecute.
- Que la prueba pase acredita la integración básica, no demuestra que el código reconstruido sea perfecto, ni que un programa analizado sea seguro.
- Ghidra puede ejecutar código de sus propios scripts Java. Trabaja solo con herramientas oficiales y programas cuyo análisis esté autorizado.
- El informe no envía binarios ni pseudocódigo a Ollama, ChatGPT o servicios externos. La carpeta temporal con la muestra y el proyecto de Ghidra se limpia al terminar.
- Las rutas con caracteres reservados por `cmd.exe` pueden rechazarse en Windows como medida preventiva.
- No publiques informes que contengan información confidencial de tu equipo.

Documentación oficial: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
