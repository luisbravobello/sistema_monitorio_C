#ifndef DATA_READER_H
#define DATA_READER_H

#include "models.h"

/*
  Lee paquetes desde un archivo de log de texto y los guarda en out_packets.
  Retorna la cantidad de paquetes leídos, o un error si no pudo abrir el archivo.
 */
int data_reader_from_log(const char *filepath, NetworkPacket *out_packets, int max_packets);

/*
  Inicia la captura de red en vivo sobre la interfaz.
  Ejecuta el callback on_packet() por cada paquete interceptado.
  Retorna 0 si arranca correctamente, o un valor distinto si ocurre un error.
 */
int data_reader_start_capture(const char *device, void (*on_packet)(NetworkPacket *));

/*
  Detiene de forma segura la captura en vivo actual.
 */
void data_reader_stop_capture(void);

#endif /* DATA_READER_H */