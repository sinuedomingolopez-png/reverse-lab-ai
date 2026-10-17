# Adaptador Rizin

La integración usa la utilidad `rz-bin` y su salida JSON:

```bash
rz-bin -Ij archivo.bin
python -m reverse_lab.cli archivo.bin --backend rizin --output reporte.json
```

Puedes seleccionar una ruta explícita con `--rizin-executable /ruta/a/rz-bin` y controlar el tiempo máximo con `--timeout 60`.

La API Python es:

```python
from reverse_lab.integrations.rizin_adapter import inspect_with_rizin

data = inspect_with_rizin("archivo.bin", executable="rz-bin", timeout=30)
print(data["metadata"])
```

El adaptador no ejecuta el binario objetivo ni utiliza el modo depurador. Los metadatos de entrada y salida se consideran no confiables. Las pruebas unitarias usan respuestas simuladas; para validar una versión instalada de Rizin se necesita una prueba de integración local.
