# Historial local y privado — Reverse Lab AI 0.10

La aplicación puede conservar una copia de un informe para consultarlo posteriormente, comparar resultados o abrir el explorador de funciones sin repetir el análisis.

**El historial está desactivado por defecto. Nunca guarda automáticamente un resultado.** Debes pulsar **Guardar en historial** y aceptar una confirmación informada.

## Utilizarlo

1. Abre Reverse Lab AI y analiza un archivo propio/autorizado, o utiliza **Funciones → Abrir informe JSON**.
2. Pulsa **Guardar en historial**. La ventana indica que el informe **completo** puede incluir pseudocódigo, símbolos, nombres y otros datos confidenciales.
3. Confirma solo si quieres conservarlo. Se creará una copia JSON local. No se envía nada a Internet.
4. Pulsa **Historial local** para abrir una lista con fecha, archivo, motor y formato.
5. Selecciona un informe y pulsa **Abrir informe** o haz doble clic para recuperarlo.
6. Para borrar una copia, selecciónala y pulsa **Eliminar seleccionado**, confirmando. El archivo analizado original no se toca.

El historial usa los mismos informes JSON que genera Reverse Lab AI. Recuperar un informe guardado no ejecuta el archivo original ni vuelve a iniciar Ghidra, Cutter o angr.

## Ubicación en tu ordenador

- Windows: `%LOCALAPPDATA%\ReverseLabAI\history`
- Linux: `$XDG_DATA_HOME/ReverseLabAI/history` (o `~/.local/share/ReverseLabAI/history`)
- macOS: `~/Library/Application Support/ReverseLabAI/history`

El historial pertenece al usuario de Windows/Linux/macOS, **no a la carpeta donde descomprimas el ZIP portable**. Por tanto, cambiar el ejecutable no elimina tus copias de historial.

## Privacidad, límites y seguridad

- Guardado **explícito** con confirmación. No hay guardado oculto ni sincronización con GitHub, Ollama o ChatGPT.
- Un máximo de **30 informes**, hasta **4 MiB por informe**. Si está lleno, debes borrar las copias manualmente: el programa no elimina las antiguas de forma silenciosa.
- Cada copia es un JSON legible guardado con un identificador aleatorio, no con el nombre del programa analizado. La escritura es atómica para reducir archivos incompletos.
- Se rechazan identificadores manipulados y enlaces simbólicos al cargar y borrar copias. Los archivos fuera de la carpeta de historial no se borran.
- La carpeta es privada en los sistemas de archivos que respetan permisos del usuario. No es cifrado: **un programa con acceso a tu cuenta podría leer el historial**. Si necesitas confidencialidad fuerte, usa cifrado del disco y evita guardar informes sensibles.
- Si borras una copia, se elimina la entrada del historial. Esto **no asegura el borrado forense** del contenido en unidades SSD o copias de seguridad; trata los datos sensibles de acuerdo con tu política de privacidad.
- El historial no demuestra que el software analizado sea seguro. Los resultados del descompilador siguen siendo aproximados.

## Pruebas

La CI comprueba guardado, recuperación, límites de tamaño, errores, borrado, protección de rutas y controles de la ventana en Linux. La compilación portable de Windows añade una prueba que crea la ventana principal con sus botones y luego la cierra, **sin analizar muestras**. Sigue recomendándose comprobar la app en un ordenador personal Windows.
