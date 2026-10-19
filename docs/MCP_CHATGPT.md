# Reverse Lab AI 0.13 — agente local y MCP

El MCP usa el SDK oficial Python 2.3.0 y llama a `workflow.analyze` en procesos
locales reales. No ejecuta la muestra. La conexión con una cuenta de ChatGPT
requiere alta y prueba desde esa cuenta; las pruebas de este repositorio no la sustituyen.

## Instalación y primer análisis privado

La aplicación base sigue admitiendo Python 3.10. El agente MCP necesita Python 3.11+.
Desde el repositorio:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install ".[mcp,desktop]"
.venv/Scripts/python -m reverse_lab.gui
```

Los motores son opcionales. LIEF requiere `pip install lief==1.0.0`.
angr 10.0.4.post1 requiere Python 3.12+: usa ese Python para un entorno conjunto
o instala angr en otro entorno y configura `REVERSE_LAB_PYTHON` con la ruta
absoluta a su intérprete. El extra `.[validation]` fija ambas versiones.
Ghidra requiere una instalación externa y un JDK compatible con su versión.
Rizin necesita `rizin` y `rz-bin` en PATH. Cutter es una aplicación externa,
con confirmación local; no ofrece control bidireccional ni se lanza desde MCP.

En **Agente MCP** puedes autorizar un archivo y seleccionar su raíz permitida.
El consentimiento especifica si el cliente recibirá solo metadatos o también
símbolos, relaciones y pseudocódigo. No se envía el binario. Con ChatGPT,
los resultados solicitados sí salen del ordenador: esa es una decisión explícita.

Equivalente en consola (sustituye rutas por las tuyas):

```powershell
.venv/Scripts/python -m reverse_lab.agent --manifest C:/private/reverse-lab/grants.json authorize C:/authorized/sample.exe --root C:/authorized --confirm-sharing
.venv/Scripts/python -m reverse_lab.agent --manifest C:/private/reverse-lab/grants.json list
.venv/Scripts/python -m reverse_lab.agent --manifest C:/private/reverse-lab/grants.json serve
```

El último comando ofrece **stdio** para un cliente MCP local compatible.
El host debe lanzar ese proceso y hablar MCP; una consola normal parecerá esperar.
Añade `--share-content` al autorizar solo si aceptas compartir contenido recuperado.
No existe una herramienta MCP para conceder permisos: debe hacerlo el propietario local.

Los ID son opacos, están vinculados a SHA-256 y caducan en una hora (máximo un día).
Si el archivo cambia hay que renovarlos. No se recorren directorios automáticamente.
`revoke ID` revoca el permiso; afecta también a resultados existentes y trabajos en curso.
Guarda el manifiesto con los permisos privados de tu usuario, fuera del repositorio
y de las raíces de muestras. No es cifrado ni una frontera frente a procesos maliciosos
que ya se ejecutan con tus propios permisos locales.

## Conexión privada validada con ChatGPT

La ruta recomendada es ahora [Secure MCP Tunnel](CHATGPT_TUNNEL.md), con agente stdio
y autenticación del transporte en OpenAI. El recorrido real desde ChatGPT con Ghidra
fue comprobado el 19-10-2026. No exige publicar HTTP ni configurar otro proveedor OAuth.
La arquitectura siguiente sigue siendo la alternativa para un endpoint HTTP público.

## Arquitectura HTTP pública con OAuth

```text
ChatGPT → HTTPS público dedicado → túnel saliente autenticado por su proveedor
        → MCP HTTP con OAuth en 127.0.0.1 → trabajador local → motor opcional
        ← resultados autorizados, paginados y marcados como datos no confiables
```

El túnel solo transporta peticiones MCP y respuestas consentidas. No se cargan
ejecutables al proveedor del túnel. Ese proveedor termina TLS y puede observar
las respuestas: no habilites contenido confidencial sin aceptar ese flujo.
No se abre un puerto entrante del router. No se instala ningún servicio automáticamente.

La parte implementada es el agente y el **servidor de recursos OAuth**. La parte
pendiente de configuración por el propietario es el proveedor OAuth, el extremo
HTTPS/túnel y el registro en ChatGPT. No hay emparejamiento remoto realizado en esta versión.

### Configurar un proveedor OAuth real

Utiliza tu proveedor OAuth/OIDC (por ejemplo Keycloak autohospedado, sin licencia comercial).
Debe ofrecer authorization-code con PKCE S256, metadatos de autorización,
registro de cliente o cliente predefinido compatible con el host, y consentimiento.
Registra exactamente el callback que muestre tu cuenta de ChatGPT; no inventes URLs.

Configura audiencia de access token igual a `https://TU-DOMINIO/mcp`, issuer exacto,
firma RS256 o ES256, `sub` de tu usuario, `client_id` o `azp`, `iat`, `exp` y `scope`.
Emite tokens breves, preferiblemente de cinco minutos. Los scopes son:

| Scope | Operaciones |
|---|---|
| `reverse:read` | Estado, motores, ID autorizados, estado/informe resumido, explicación |
| `reverse:analyze` | Iniciar análisis |
| `reverse:content` | Nombres, tablas, funciones, referencias y pseudocódigo consentidos localmente |
| `reverse:cancel` | Cancelar un análisis |

Los permisos OAuth no sustituyen la autorización local de cada archivo.
Solo se admite el `sub` del propietario configurado. No se aceptan tokens de otros usuarios.
Descarga las **claves públicas** JWKS de tu propio proveedor a un archivo privado local.
El agente no descarga JWKS desde URLs recibidas ni envía datos al proveedor.
Mantén las claves actualizadas al rotarlas. Quitarlas del archivo revoca el acceso
inmediatamente; también puedes detener el agente o revocar los archivos.

### Iniciar HTTP y túnel

Copia `examples/agent-http.example.json` fuera del repositorio y rellena sus campos.
El panel **Agente MCP → Iniciar HTTP con configuración…** lo lee y permite detener
el proceso. El portable usa un agente Python externo; no incorpora el SDK ni los motores.
En consola:

```powershell
.venv/Scripts/python -m reverse_lab.agent --manifest C:/private/reverse-lab/grants.json serve --transport http --issuer https://TU-IDP/ --resource-url https://TU-DOMINIO/mcp --jwks C:/private/reverse-lab/provider-public-keys.json --owner-subject TU-SUBJECT
```

HTTP falla cerrado si faltan los parámetros OAuth. Siempre escucha en `127.0.0.1:8765`.
Solo admite el Host configurado o loopback, limita cuerpo a 16 KiB y conexiones
simultáneas a 16. No desactives esas verificaciones para resolver un error del proxy.

Como opción de desarrollo, tras instalar y autenticar tú mismo ngrok:

```text
ngrok http 8765
```

Usa su dominio asignado como TU-DOMINIO desde el principio. El agente ngrok sale
desde tu equipo. No guardes su token en Git ni habilites grabación de respuestas
sensibles. No coloques un login HTML interactivo delante de `/mcp` que impida
los bearer tokens MCP. La opción gratuita tiene cuotas y condiciones; no garantiza
servicio ilimitado. El código local es gratuito y no consume una API de pago.
No se ha creado cuenta, contratado plan ni activado túnel en esta sesión.

### Alta y prueba manual en ChatGPT

1. Comprueba que tu cuenta o administrador permite añadir MCP personalizado.
2. En la interfaz de plugins/apps disponible en tu cuenta, añade el servidor HTTPS
   con ruta `/mcp`, configura OAuth y completa login y consentimiento.
3. Instala/selecciona el conector en un chat donde esté disponible. Este proceso
   no puede insertar herramientas nuevas automáticamente en un chat ya abierto.
4. Autoriza localmente solo el ELF sintético de prueba. Pide estado, lista de motores,
   archivos autorizados y análisis por ID; consulta después estado e informe.
5. Si autorizaste contenido, prueba funciones, pseudocódigo y llamada entre funciones.
6. Revoca el archivo localmente y comprueba que nuevas lecturas se rechazan.

Solo después de observar ese recorrido desde ChatGPT puede declararse conectado.
La prueba HTTP automatizada usa JWT efímeros de prueba: valida firma, audiencia,
issuer, usuario, scopes y rutas reales, pero **no prueba el login OAuth externo**.

## Contratos y límites

14 herramientas: `reverse_lab_status`, `list_analysis_engines`, `list_authorized_files`,
`analyze_file`, `get_analysis_status`, `get_analysis_report`, `list_functions`,
`inspect_function`, `get_pseudocode`, `get_call_graph`, `get_control_flow_graph`,
`compare_reports`, `explain_analysis`, `cancel_analysis`.

Los esquemas vienen del SDK, con ID hexadecimal, enum de motores y límites tipados.
No se aceptan rutas, ejecutores, comandos de consola, URL de muestras ni scripts del cliente.
Las listas admiten `offset` y `limit` (1–100); retornan `total` y `next_offset`.
`get_analysis_report` ofrece resumen o páginas de secciones, símbolos/importaciones/exportaciones,
bibliotecas y cabecera según el motor. `get_pseudocode` da fragmentos de 4000 caracteres.
Las respuestas están acotadas a 64 KiB. Si una página no cabe se pide una menor.

`analyze_file(file_id, engine)` retorna un ID de trabajo. Estados reales: queued,
running, completed, failed, cancelled, timed_out o memory_limit. No se inventan porcentajes.
La detección de un motor no demuestra validación de ese motor. Los errores públicos
no contienen rutas, stderr ni secretos. Una incidencia de Ghidra produce fallo, no éxito.

Una tarea activa, 16 registros transitorios como máximo, entrada de 32 MiB, 180 segundos
por defecto (5–600), memoria de 2 GiB (256 MiB–4 GiB), resultado interno de 16 MiB.
Los resultados caducan tras 30 minutos y se eliminan al cerrar el agente; no son historial.
Las copias temporales de muestras y resultados se limpian al terminar cada trabajo.

Windows usa Job Objects con memoria agregada y cierre del árbol. Unix usa grupo de
procesos y RLIMIT más vigilancia de RSS. Estos límites no proporcionan un sandbox
contra vulnerabilidades del parser, escape deliberado o acceso de red del motor.
Para binarios desconocidos utiliza una VM; la ejecución simbólica sigue sin exponerse.

`explain_analysis` devuelve evidencias, un resumen determinista e incógnitas. ChatGPT
puede razonar sobre ellas, identificando hipótesis. Ollama conserva su ruta local
optativa con confirmación; el servidor no invoca IA de pago automáticamente.

## Verificación y referencias

```powershell
python -m unittest discover -s tests -v
python -m unittest discover -s integration_tests -v
python -m unittest discover -s ui_tests -v
```

Las pruebas generan muestras propias, nunca las ejecutan, y omiten motores ausentes
con una etiqueta explícita. `test_mcp_wire` usa cliente oficial por stdio y HTTP;
`test_job_limits` usa procesos inertes de prueba para comprobar cancelación y timeout,
sin atribuir esa prueba a un motor auténtico.

Documentación consultada el 19-10-2026:
- [MCP oficial Python y licencia MIT](https://github.com/modelcontextprotocol/python-sdk)
- [MCP en ChatGPT](https://developers.openai.com/plugins/build/mcp-server)
- [OAuth en ChatGPT](https://developers.openai.com/plugins/build/auth)
- [Alta y prueba desde ChatGPT](https://developers.openai.com/plugins/build/app-quickstart)
- [Registro de clientes Keycloak](https://www.keycloak.org/securing-apps/client-registration)
- [Cuotas de ngrok](https://ngrok.com/pricing)
