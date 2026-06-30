#ifndef VIEWMODEL_H
#define VIEWMODEL_H

#include "models.h"

/*
 * Convierte los eventos a formato JSON para el cliente en Python.
 * Importante: debes liberar la memoria del string resultante usando free().
 */
char *viewmodel_events_to_json(ThreatEvent *events, int n);

/*
  Se encarga para filtrar solo las amenazas confirmadas y las ordena desde la más crítica a la más leve.
 */
char *viewmodel_alerts_to_json(ThreatEvent *events, int n);

/*
 * Genera un JSON con el resumen general del tráfico
 * cantidad de paquetes, tipos de ataque y niveles de severidad.
 */
char *viewmodel_statistics_to_json(ThreatEvent *events, int n);

#endif /* VIEWMODEL_H */