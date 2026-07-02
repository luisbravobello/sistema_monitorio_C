#ifndef API_SERVER_H
#define API_SERVER_H

#include "models.h"

/*
 * Inicia el servidor HTTP en el puerto indicado y se queda escuchando hasta llamar a api_server_stop().
 * El arreglo de eventos (ThreatEvent) y su mutex se manejan internamente, no hay que inicializarlos.
 * Rutas disponibles
 * POST /start[?device=X] -> Inicia la captura de paquetes.
 * POST /stop             -> Detiene la captura.
 * GET /events            -> Devuelve todos los eventos (JSON).
 * GET /alerts            -> Devuelve las alertas (JSON).
 * GET /statistics        -> Devuelve las estadísticas (JSON).
 * GET /search?ip=&port=  -> Filtra los eventos por IP o puerto.
 */
void api_server_start(int port);

/*
 Apaga el servidor HTTP de forma segura y libera el hilo principal.
 */
void api_server_stop(void);

/*
 Guarda un evento en el arreglo interno de forma segura (thread-safe).
 Está diseñada para usarse directamente desde el hilo de captura sin chocar con las peticiones web.
 */
void api_server_add_event(const ThreatEvent *event);

#endif /* API_SERVER_H */