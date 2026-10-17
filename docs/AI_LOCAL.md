# Interpretación local de informes — versión 0.3.0

## 1. Explicación sin IA (funciona sin instalar nada adicional)

```bash
python -m reverse_lab.report_cli explain informe.json
```

Esta opción genera una descripción factual del archivo, formato, tamaño, SHA-256, motor y funciones exportadas. **No utiliza modelos de lenguaje** y evita inventar el comportamiento del ejecutable.

En la interfaz, tras analizar un archivo pulsa **Explicar**.

## 2. IA local opcional mediante Ollama

Reverse Lab AI puede consultar un modelo instalado *en tu ordenador*. La conexión de esta versión se limita al servicio HTTP local de Ollama en el puerto 11434 y **solo se realiza si eliges esta opción**.

1. Instala Ollama desde https://ollama.com/download
2. Descarga un modelo gratuito disponible en Ollama:

```bash
ollama pull qwen2.5:3b
```

3. Asegúrate de que Ollama está ejecutándose y analiza o guarda un informe JSON.
4. Solicita explícitamente la explicación por IA:

```bash
python -m reverse_lab.report_cli explain informe.json --ollama --model qwen2.5:3b
```

O pulsa **Explicar → Explicar mediante IA local (Ollama)** en la interfaz y confirma la consulta.

El modelo Qwen2.5 3B ocupa aproximadamente 1,9 GB de descarga, además de memoria para ejecutarse. Revisa su licencia específica para el uso previsto: no todos los modelos Qwen tienen la misma licencia.

## Privacidad y límites

El conector envía al servicio local **solo** formato, tamaño, SHA-256, motor, recuento de funciones exportadas y estado de análisis. No envía ejecutables, código descompilado, nombres de funciones, logs, rutas ni el JSON completo. Se bloquean destinos externos, proxies y redirecciones HTTP.

**No hay una conexión con ChatGPT en esta versión**. Ollama es un motor local opcional. Una explicación generativa puede equivocarse; no debe considerarse auditoría de malware, prueba de seguridad o recuperación exacta del código fuente. Instala y ejecuta el modelo localmente antes de utilizarlo; las pruebas automáticas simulan sus respuestas.
