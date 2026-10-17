# Comparar informes JSON de Reverse Lab AI

A partir de la versión 0.3.0 puedes comparar dos resultados guardados sin analizar de nuevo el ejecutable.

## Desde la interfaz

Abre `reverse-lab-gui` o `python -m reverse_lab.gui`, pulsa **Comparar JSON** y selecciona dos informes.

Se mostrará: nombre del archivo, motor empleado, igualdad del SHA-256, cambios de tamaño/formato, y funciones comunes, añadidas o desaparecidas **solo cuando ambos informes tengan listas de funciones exportadas**. Puedes guardar el texto de comparación.

## Desde terminal

```bash
python -m reverse_lab.report_cli compare before.json after.json --format text
python -m reverse_lab.report_cli compare before.json after.json --format json --output comparison.json
```

Si instalaste el paquete, también funciona:

```bash
reverse-lab-compare before.json after.json --format text
```

Los informes deben incluir los campos `filename`, `sha256`, `size_bytes` y `format`. El lector rechaza archivos JSON inválidos y archivos de más de 16 MiB. Los nombres de funciones y direcciones son datos no confiables. La comparación por función usa el par (nombre, dirección): si cambian las direcciones por relocalización, pueden aparecer falsos positivos. Distintos SHA-256 no demuestran cambios de comportamiento, y coincidir no demuestra seguridad.

No se ejecutan archivos y no se realizan conexiones de red.
