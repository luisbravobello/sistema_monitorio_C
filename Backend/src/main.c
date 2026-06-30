#include <stdio.h>
#include "api_server.h"

int main(int argc, char **argv) {
    int port = 8080;

    printf("Monitor de Amenazas — servidor escuchando en http://localhost:%d\n", port);

    /* El arreglo de amenazas se manejan de forma interna y segura en api_server.c */
    api_server_start(port); 

    return 0;
}