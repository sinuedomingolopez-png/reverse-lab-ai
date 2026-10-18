# Explorador unificado de funciones — Reverse Lab AI 0.6

La ventana **Explorador de funciones** conecta en un único lugar las funciones, el pseudocódigo C aproximado y las referencias del mapa de llamadas. Funciona en tu ordenador y **no realiza conexiones externas**.

## Desde la interfaz

1. Abre Reverse Lab AI con `python -m reverse_lab.gui` o con el lanzador de Windows.
2. Analiza un archivo autorizado con **Ghidra**, marcando las exportaciones que quieras: funciones, pseudocódigo y/o mapa de llamadas. El motor externo debe estar instalado.
3. En la pestaña **Funciones**, pulsa **Explorar funciones** o haz doble clic sobre una función. En **Mapa de llamadas**, un doble clic abre la ficha de la función destino.
4. Busca por nombre o dirección: admite mayúsculas y minúsculas indistintamente.
5. La ventana muestra la ficha de la función, su pseudocódigo disponible y dos listas: **Llama a** y **Llamada por**. Haz doble clic en una relación para visitar la función asociada. Pulsa **Anterior** para regresar a la función previa.

## Usar informes JSON guardados

También puedes abrir un archivo `.json` existente en **Funciones → Abrir informe JSON**. Reverse Lab AI comprueba el esquema y el tamaño del informe antes de cargarlo (máximo 16 MiB). No necesitas repetir el análisis ni ejecutar Ghidra.

El índice une datos provenientes de `analysis.functions`, `analysis.pseudocode` y `analysis.call_graph` por dirección de entrada. Puede incluir funciones que **solo** aparecen en relaciones de llamadas, aunque no se hayan exportado en el listado principal.

## Límites y alcance

- Hasta 10.000 funciones en el índice por defecto. Para no ralentizar la interfaz, la búsqueda presenta un máximo de 500 resultados simultáneos.
- Pseudocódigo acotado a 8.000 caracteres por función para su visualización y hasta 200 relaciones entrantes/salientes por ficha.
- El pseudocódigo es una reconstrucción aproximada, **no el código fuente original**.
- Las llamadas indirectas, dinámicas y destinos no resueltos pueden no estar presentes.
- La ficha es de **solo lectura**: los nombres y el pseudocódigo se tratan como datos no confiables, nunca como comandos ni instrucciones para una IA.
- La ausencia de un resultado no demuestra que la función no exista; puede deberse a límites o a datos incompletos.
- Si el programa contiene secretos o información propietaria, no publiques su informe JSON.

## Verificación

El módulo de indexación cuenta con pruebas de búsqueda, relaciones, límites, entradas inválidas y datos potencialmente peligrosos. La interfaz se ha probado con una ventana de Tkinter en un entorno gráfico virtual Linux. La integración con una instalación real de Ghidra en Windows sigue pendiente.
