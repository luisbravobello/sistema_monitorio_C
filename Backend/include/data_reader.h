#ifndef DATA_READER_H
#define DATA_READER_H

#include "models.h"

#define DR_DEVICE_NAME_LEN 128
#define DR_DEVICE_DESC_LEN 256
#define DR_ERRBUF_LEN       256

/*
  Lee paquetes desde un archivo de log de texto y los guarda en out_packets.
  Retorna la cantidad de paquetes leídos, o un error si no pudo abrir el archivo.
 */
int data_reader_from_log(const char *filepath, NetworkPacket *out_packets, int max_packets);

/*
  Indica si el binario fue compilado con captura real (Npcap/libpcap) o
  si va a usar el simulador interno. Útil para que la API/UI le avisen
  al usuario si lo que ve es tráfico real o de prueba.
  Retorna 1 = captura real disponible, 0 = modo simulado.
 */
int data_reader_has_real_capture(void);

/*
  Lista las interfaces de red disponibles para captura (adaptadores Npcap
  en Windows, o interfaces libpcap en Linux/macOS).
  Llena los arreglos out_names/out_descs (hasta max_devices) y retorna
  la cantidad encontrada, o -1 si hubo un error (revisar errbuf).
 */
int data_reader_list_devices(char out_names[][DR_DEVICE_NAME_LEN],
                              char out_descs[][DR_DEVICE_DESC_LEN],
                              int max_devices,
                              char *errbuf, size_t errbuf_len);

/*
  Abre la interfaz para captura en vivo (paso SINCRÓNICO).
  Si device es NULL o cadena vacía o "any" (que Npcap no soporta), se
  autoselecciona la primera interfaz disponible que no sea loopback.
  Retorna 0 si pudo abrir el dispositivo, -1 si falló (con el motivo en errbuf).
  Al confirmar éxito, out_device_used (si no es NULL) recibe el nombre real
  del dispositivo que quedó abierto.
 */
int data_reader_open_capture(const char *device, char *errbuf, size_t errbuf_len,
                              char *out_device_used, size_t out_device_used_len);

/*
  Corre el bucle de captura (BLOQUEA el hilo actual) sobre el dispositivo
  previamente abierto con data_reader_open_capture(). Ejecuta on_packet()
  por cada paquete interceptado hasta que se llame data_reader_stop_capture().
  Debe llamarse siempre después de un data_reader_open_capture() exitoso.
 */
void data_reader_run_capture(void (*on_packet)(NetworkPacket *));

/*
  Detiene de forma segura la captura en vivo actual y cierra el dispositivo.
 */
void data_reader_stop_capture(void);

#endif /* DATA_READER_H */
