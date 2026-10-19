# Hoja de ruta — 0.13

## Implementado

Se conservan CLI, análisis básico, informes JSON, escritorio Tkinter, explorador de funciones, pseudocódigo, mapa de llamadas, comparador, historial privado optativo, diagnóstico y Ollama opcional. La versión 0.13 añade:

- Extracción real ampliada de LIEF, Rizin y angr; CFG visible en el escritorio.
- Ghidra headless con exportaciones no vacías verificadas con el motor real.
- Servidor MCP oficial con catorce herramientas, stdio y HTTP, contratos paginados y respuestas acotadas.
- Autorizaciones locales por archivo, raíz permitida, hash, caducidad y consentimiento separado para contenido.
- Trabajos aislados en procesos con límites de recursos, cancelación del árbol y resultados temporales revocables.
- Verificación OAuth con claves públicas fijadas, audiencia, emisor, propietario y permisos por operación.
- Panel local de permisos e inicio/parada del agente; arrastrar y soltar opcional; tema oscuro.
- Pruebas con cliente MCP oficial por stdio y HTTP autenticado; workflows de motores auténticos y portable.

Consulta [auditoría](AUDIT_2026_10_19.md), [validación](VALIDATION_0_13.md) y [configuración MCP](MCP_CHATGPT.md) para separar implementación y evidencia.

## Pendiente de validación real

- Navegación manual en Cutter. Su apertura externa está probada; no hay sincronización bidireccional.
- Ollama con un modelo local instalado: se mantiene el conector existente, sin nueva validación de generación en esta entrega.
- Uso prolongado y muestras autorizadas más variadas; los ensayos actuales usan archivos sintéticos.
- Portable en otros equipos Windows y comportamiento frente a antivirus. El EXE sigue sin firma.

## Pendiente de acción manual del propietario

- Configurar proveedor OAuth/OIDC, claves públicas, identidad y dominio HTTPS/túnel saliente.
- Registrar la aplicación MCP desde una cuenta de ChatGPT que permita hacerlo.
- Completar autorización y análisis de extremo a extremo desde esa cuenta. Hasta entonces, ChatGPT permanece `not_verified`.

## Pendiente de desarrollar

- Control bidireccional de Cutter.
- Emparejamiento guiado y aprovisionamiento automático del proveedor OAuth/túnel.
- Aislamiento reforzado con VM/contenedor para archivos hostiles; no se habilita ejecución simbólica.
- Firma del ejecutable y actualización automática, si se decide adoptarlas.

## Política técnica

Solo analizar software autorizado. No ejecutar binarios objetivo. Mantener motores opcionales y revisar sus licencias. Los nombres y fragmentos recuperados son datos no confiables, nunca instrucciones del asistente.
