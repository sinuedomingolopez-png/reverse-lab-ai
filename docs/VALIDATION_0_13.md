# Validación de Reverse Lab AI 0.13.0

Fecha: 2026-10-19. Repositorio existente, base 0.12 aeb2637. Rama feature/local-mcp-lab; [PR 17](https://github.com/sinuedomingolopez-png/reverse-lab-ai/pull/17). Solo muestras sintéticas; ningún ejecutable objetivo se ejecutó ni se subió a servicios.

## Implementado y probado

- 192 pruebas unitarias: correctas, cuatro omisiones condicionadas. Los dobles de prueba se distinguen de las integraciones siguientes.
- Ocho pruebas de interfaz sobre ventanas Tkinter reales en Windows: correctas. Conservan navegación, historial voluntario y diagnóstico, y verifican el nuevo panel MCP.
- Ocho pruebas de integración completas en Windows: correctas, sin omisiones en el entorno de validación. Incluyen los cuatro motores auténticos, protocolo MCP stdio y HTTP con cliente oficial, rechazo sin token, scopes, revocación, límites y cancelación.
- LIEF 1.0.0 reconoce ELF, PE y Mach-O generados. El PE incluye una importación ExitProcess, KERNEL32.dll y una exportación synthetic_helper verificadas. Los archivos mínimos no acreditan cobertura general de cada formato.
- Rizin 0.9.1 encuentra las dos funciones sintéticas, con secciones y símbolos.
- Ghidra 12.1.4 / JDK Temurin 25.0.4.1+1 ejecuta los scripts Java y recupera dos funciones, dos pseudocódigos no vacíos y una llamada. El cliente MCP solicita también estas evidencias reales.
- angr 10.0.4.post1 / Python 3.12.14 produce tres funciones, cuatro nodos y tres aristas con CFGFast en un worker. No se habilita ejecución simbólica. La aplicación principal probada usa Python 3.11.9 y el intérprete angr externo.
- Cutter 2.5.0 se detecta y abre como proceso externo con el ELF generado. Su navegación visual no se considera validada.
- MCP oficial Python SDK 2.3.0: catorce herramientas reales, incluidas todas las solicitadas y get_control_flow_graph. Entradas tipadas, paginación, esquema estructurado, errores MCP, reto OAuth por scope y presupuesto total de respuesta limitado.
- Autorizaciones locales por raíz, archivo regular, hash, caducidad e ID opaco; consentimiento adicional para símbolos/pseudocódigo. La revocación afecta a resultados y trabajos. Regresión de concurrencia grant/revoke corregida y probada.
- Límites de tiempo, memoria, archivo y trabajos; pruebas con procesos reales verifican cancelación/timeout del árbol y que un Job Object Windows bloquea una reserva de memoria superior al límite. Los procesos inertes de esta prueba no son programas analizados.
- HTTP solo loopback, verificador OAuth con JWKS públicas fijadas, emisor, audiencia, firma, propietario y scopes. Pruebas con tokens de una clave efímera local; no representan un login de proveedor real.
- Portable Windows x64 construido con PyInstaller 6.22.3: autoprueba offline, diagnóstico, recursos empaquetados y creación de ventana real correctos. ZIP y SHA-256 acompañan la entrega.
- Compilación Python y parseo de todos los YAML de workflows. Se corrigió un YAML previo inválido que impedía ejecutar el workflow de motores reales.
- Consulta OSV del entorno Python 3.12 de validación: 73 paquetes y ninguna vulnerabilidad conocida devuelta en esa consulta. No acredita ausencia de vulnerabilidades ni cubre los ejecutables nativos.

Las evidencias se limitan al entorno y muestras indicados. Los workflows deben revisarse sobre el commit final en la PR; ejecuciones previas no acreditan cambios posteriores.

## Implementado pero pendiente de validación real

- OAuth/OIDC con un proveedor y cuenta reales, túnel HTTPS y autorización desde ChatGPT. Las pruebas locales cubren el servidor de recursos y cliente MCP, no la cuenta de ChatGPT.
- Uso del portable en otros equipos Windows y frente a sus políticas antivirus; el ejecutable no está firmado.
- Generación con Ollama y un modelo real: se conserva el conector local, sin nueva prueba de modelo instalado.
- Navegación manual en Cutter y uso prolongado con más muestras autorizadas.

## Pendiente de autorización/configuración manual

El propietario debe elegir/configurar proveedor OAuth, identidad, claves públicas y dominio/túnel, registrar el MCP en su cuenta de ChatGPT y realizar el consentimiento. La guía [MCP_CHATGPT.md](MCP_CHATGPT.md) incluye configuración, arranque/parada, permisos, revocación y prueba final. ChatGPT sigue expresamente `not_verified` hasta completar ese recorrido.

## Pendiente de desarrollar

Emparejamiento guiado y aprovisionamiento automático de OAuth/túnel; integración bidireccional con Cutter; aislamiento reforzado mediante VM/contenedor para muestras hostiles; firma y actualización automática del portable. Ninguna de estas capacidades se presenta como existente.

## Privacidad y límites

El análisis permanece local. Los resultados que un cliente remoto solicite sí atraviesan el túnel y llegan a ese cliente con el consentimiento concedido. El proveedor del túnel que termina TLS puede observarlos. El binario no se expone como recurso MCP. No autorices contenido confidencial sin aceptar ese flujo. Los límites de procesos no equivalen a un entorno de seguridad completo. Las autorizaciones locales no protegen frente a otro proceso malicioso con los mismos permisos de usuario.
