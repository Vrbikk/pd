//
// Created by vrbik on 17.11.17.
//

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "libndpi-2.1.0/libndpi/ndpi_api.h"
#include <netinet/in.h>
#include "ndpi_util.h"

#ifndef PD_DB_H
#define PD_DB_H

MYSQL *conn;
MYSQL_RES *res;
MYSQL_ROW row;

void init_conn();
void create_table_protocol(int id, const char *name);
bool ip_exists(const char *ip, int id, struct ndpi_detection_module_struct *ndpi_struct);
void sql_query(const char *query);
void close_conn();
void insert_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);
void update_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);

#endif //PD_DB_H
