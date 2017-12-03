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

struct specific_proto{
    int *protocols;
    unsigned char count;
    bool all;
};

MYSQL *conn;
MYSQL_RES *res;
MYSQL_ROW row;

int host_id;
int protocol_id;

void set_specific_proto(struct specific_proto *sp, const char *arg);
void parse_config(struct specific_proto *sp);
void init_conn(struct specific_proto *sp);
void create_table_protocol(int id, const char *name);
bool ip_exists(const char *ip, int id, struct ndpi_detection_module_struct *ndpi_struct);
void sql_query(const char *query);
void close_conn();
void insert_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);
void update_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);

int last_insert_id();
unsigned int ip_to_int (const char * ip);
bool src_ip_exists(struct ndpi_flow_info *flow);
void insert_host(struct ndpi_flow_info *flow);
void update_host();

bool protocol_exists(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);
void insert_protocol(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct);
void update_protocol();

bool conn_exists(struct ndpi_flow_info *flow);
void insert_conn(struct ndpi_flow_info *flow);
void update_conn(struct ndpi_flow_info *flow);

#endif //PD_DB_H
