# ChatGPT mediante Secure MCP Tunnel

El 19-10-2026 se completó una prueba real desde una cuenta de ChatGPT con Reverse Lab AI 0.13.0: análisis Ghidra de un ELF sintético, dos funciones, dos pseudocódigos y una llamada. La función auxiliar devuelve 0x2a. La muestra no se ejecutó. Esto acredita ese recorrido, no configura automáticamente otras cuentas.

## Ruta privada recomendada

ChatGPT → Secure MCP Tunnel de OpenAI → cliente oficial saliente → agente stdio → motor local.

El servidor no necesita URL pública, puerto entrante ni otro proveedor OAuth en esta modalidad. La identidad y acceso al túnel se controlan en OpenAI; el agente mantiene sus permisos locales por archivo. Un servidor HTTP público debe conservar la verificación OAuth documentada por separado.

1. Abre [Tunnels](https://platform.openai.com/settings/organization/tunnels) en tu organización personal. Crea un túnel exclusivo y asócialo al espacio de ChatGPT que lo usará.
2. Crea una clave de ejecución restringida a **Tunnels: Read y Use**. No concedas modelos, archivos ni administración. Usa caducidad y conserva la clave en un almacén local protegido. Nunca la pegues en chats, argumentos, logs o Git.
3. Descarga el cliente desde el enlace oficial de esa página y verifica SHA-256. Consulta `tunnel-client help quickstart` para la versión instalada.
4. Configura un perfil stdio con el Python del agente, `--manifest` privado y `serve`. Usa una referencia de entorno para la clave. En Windows escribe las rutas de la cadena de comando con barras `/` para evitar que su analizador consuma barras inversas.
5. Ejecuta `doctor --profile NOMBRE --explain`. Arranca con `runtimes connect`, comprueba salud, readiness y polling, y mantenlo activo durante el uso.
6. En [ChatGPT Plugins](https://chatgpt.com/plugins), añade un MCP personalizado, selecciona **Túnel**, su ID y **Sin autenticación** de aplicación para este agente stdio. El transporte sigue protegido por la cuenta y permisos del túnel; no se publica un endpoint anónimo.
7. Instala el complemento y prueba `reverse_lab_status`. Autoriza localmente una muestra sintética, inicia el análisis, consulta sus evidencias y revoca después el permiso. Comprueba que `list_authorized_files` queda vacío.

La instalación validada usa una clave cifrada con Windows DPAPI fuera del repositorio y accesos locales de conexión/parada. No instala un servicio ni inicio automático del sistema. El ordenador, cliente y agente deben permanecer activos. Al caducar la clave hay que renovarla; la instalación de prueba usa 30 días.

Los resultados consultados llegan a OpenAI con el consentimiento concedido. El binario no se ofrece como recurso MCP. El campo local `chatgpt_connection: not_verified` expresa que el servidor no observa por sí mismo el estado de una cuenta: la evidencia válida de extremo a extremo es la llamada realizada desde ChatGPT. Disponibilidad de un motor y validación general también son conceptos diferentes.

Fuentes: [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels), [alta de MCP](https://developers.openai.com/api/docs/guides/custom-mcp-server) y [cliente oficial](https://github.com/openai/tunnel-client).
