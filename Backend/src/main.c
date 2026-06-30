#include <stdio.h>
#include "api_server.h"

int main(int argc, char **argv) {
    int port = 8080;

    printf("Monitor de Amenazas — servidor escuchando en http://localhost:%d\n", port);

    // El arreglo compartido de ThreatEvent y su mutex viven dentro de
    // api_server.c (variables estáticas + pthread_mutex_t), así que no
    // hace falta inicializar nada acá: el módulo se encarga de
    // protegerlos entre el hilo de captura (arranca con POST /start) y
    // el hilo que atiende las peticiones HTTP.

    api_server_start(port); // bloquea aquí hasta que llamen a api_server_stop()

    return 0;
}