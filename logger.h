//
// Created by vrbik on 11.11.17.
//

#ifndef PD_LOGGER_H
#define PD_LOGGER_H

#include <time.h>
#include <stdio.h>
#include "libndpi-2.1.0/libndpi/ndpi_api.h"
#include <netinet/in.h>
#include "ndpi_util.h"

const char* logging_file;
FILE *log_ptr;

void setup_logger(const char *file);
void logger(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);

#endif //PD_LOGGER_H
