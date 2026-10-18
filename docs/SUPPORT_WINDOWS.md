# Soporte y diagnóstico sin datos privados — Reverse Lab AI 0.11

Esta versión permite revisar qué motores de análisis están detectados y si los scripts de Ghidra están incluidos, sin subir archivos, sin ejecutar binarios y sin recopilar información personal.

## Si ReverseLabAI.exe no abre en Windows

1. Descarga el ZIP portable **desde el workflow oficial de GitHub** y extrae toda la carpeta ReverseLabAI, incluida `_internal`.
2. Haz doble clic en **DIAGNOSTICO-WINDOWS.cmd**, dentro de esa carpeta. Este archivo abre una consola y pide al ejecutable que cree un diagnóstico técnico **sin iniciar la interfaz**.
3. El resultado se crea en la carpeta temporal de tu cuenta de Windows con nombre `ReverseLabAI-diagnostico.json`. El script indica esa ubicación.
4. Abre ese JSON con el Bloc de notas. Si la comprobación funciona, verás el estado del paquete (`ready` o `incomplete`) y el estado de herramientas como `ghidra`, `rizin`, `cutter`, `angr` y `lief`.

Si la ventana sí abre, pulsa **Guardar diagnóstico** y elige dónde guardar el archivo. No se guarda nada automáticamente.

## Alternativa desde PowerShell

Desde la carpeta que contiene el ejecutable:

```powershell
.\ReverseLabAI.exe --diagnostics-output "$env:TEMP\ReverseLabAI-diagnostico.json"
Get-Content "$env:TEMP\ReverseLabAI-diagnostico.json"
```

Desde la versión Python (sin empaquetar):

```powershell
py -m reverse_lab.support
py -m reverse_lab.support --output ".\diagnostico.json"
```

## Qué contiene el informe

- Versión del laboratorio y familia de sistema operativo (Windows, macOS o Linux).
- Versión mayor y menor del intérprete de Python incluido/instalado.
- Si se está ejecutando un ejecutable portable.
- Estado de integridad de scripts Java incluidos con Reverse Lab AI.
- Si Ghidra, Rizin, Cutter, angr y LIEF están detectados, ausentes o sin poder determinarse.

**No incluye** nombres de usuario, rutas completas, nombres de muestras, SHA-256 de archivos analizados, contenido de programas, pseudocódigo, variables de entorno, tokens ni logs. No hay telemetría, conexión a la nube ni archivos analizados para crear este informe. El código usa una lista explícita de campos permitidos; no copia los valores de los resultados de detección.

No obstante, cualquier archivo exportado debe revisarse antes de compartirlo.

## Cómo interpretar los estados

- `bundle.status: ready`: los tres scripts Java de Ghidra están presentes; esto no indica que Ghidra esté instalado ni que funcione.
- `bundle.status: incomplete`: faltan scripts necesarios; extrae de nuevo el ZIP completo.
- `tools.ghidra: detected`: se encontró un lanzador, pero no se ha comprobado la versión de Java ni el funcionamiento del análisis.
- `tools.angr: missing`: angr no está detectado en el entorno Python de la aplicación. En versión portable el uso de angr requiere un intérprete Python externo configurado por separado.
- `tools_status: error`: alguna comprobación local no pudo realizarse; no se incluyen detalles privados en el archivo.

## Limitaciones

La autoprueba del programa empaquetado comprueba la integridad básica. GitHub Actions puede carecer de un escritorio Windows interactivo, así que una prueba gráfica bloqueada se marca `not_verified`, nunca se convierte en éxito. La verificación completa de la ventana y de motores reales necesita una prueba en un Windows con sesión gráfica.

El EXE portable no está firmado digitalmente. No desactives SmartScreen ni otras protecciones para ejecutarlo. Para muestras desconocidas utiliza una VM aislada.
