#ifndef SORT_H
#define SORT_H

#include "models.h"

/*
 * Ordena los eventos, desde el más antiguo al más reciente .
 */
void sort_by_timestamp(ThreatEvent *events, int n);

/*
 * Ordena los eventos según su nivel de amenaza, desde el más crítico al más leve.
 */
void sort_by_severity(ThreatEvent *events, int n);

#endif /* SORT_H */