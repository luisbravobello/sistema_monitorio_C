#ifndef DETECTOR_H
#define DETECTOR_H

#include "models.h"

/*
 Evalúa un paquete contra las reglas de detección (PORT_SCAN, SSH_BRUTE).
 Si encuentra una amenaza, guarda los detalles en out_event y retorna 1.
 Si el paquete es seguro, retorna 0 y deja out_event intacto.
 */
int detector_analyze(const NetworkPacket *packet, ThreatEvent *out_event);

#endif /* DETECTOR_H */