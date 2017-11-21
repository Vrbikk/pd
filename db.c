//
// Created by vrbik on 17.11.17.
//

#include "db.h"

char *server = "localhost";
char *user = "pd";
char *password = "pd";
char *database = "pd";

void create_table_protocol(int id, const char *name){
    char text[600];
    snprintf( text, sizeof(text),
            "CREATE TABLE IF NOT EXISTS`proto_%d_%s` (\n"
            "  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,\n"
            "  `src_ip` varchar(20) DEFAULT NULL,\n"
            "  `pkts` int(11) DEFAULT '0',\n"
            "  `bytes` int(11) DEFAULT '0',\n"
            "  `flows` int(11) DEFAULT '0',\n"
            "  `first` datetime DEFAULT CURRENT_TIMESTAMP,\n"
            "  `last` datetime DEFAULT CURRENT_TIMESTAMP,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;", id, name);

    sql_query(text);
}

bool ip_exists(const char *ip, int id, struct ndpi_detection_module_struct *ndpi_struct){
    char text[150];
    snprintf( text, sizeof(text), "select * from proto_%d_%s WHERE src_ip=\"%s\"", id, ndpi_get_proto_name(ndpi_struct, id), ip);
    sql_query(text);

    if(mysql_errno(conn) == 1146){
        create_table_protocol(id, ndpi_get_proto_name(ndpi_struct, id));
        return false;
    }

    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

void sql_query(const char *query){
    mysql_free_result(res);
    if (mysql_query(conn, query) && (mysql_errno(conn) != 1146)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }
    res = mysql_use_result(conn);
}

void close_conn(){
    mysql_close(conn);
}

void init_conn(){
    conn = mysql_init(NULL);

    if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }
}

void insert_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){
    char text[200];
    snprintf(text, sizeof(text), "insert into proto_%d_%s (src_ip, pkts, bytes, flows) VALUES (\"%s\",%d,%d,%d)",
             flow->detected_protocol.app_protocol, ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol),
             flow->src_name, flow->src2dst_packets + flow->dst2src_packets, flow->src2dst_bytes+flow->dst2src_bytes, 1);
    sql_query(text);

    printf("\npo insertu\n");
}

void update_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){

    char text[200];
    snprintf(text, sizeof(text), "UPDATE proto_%d_%s set pkts=%d, bytes=%d, flows=%d, last=now() WHERE id=%d",
             flow->detected_protocol.app_protocol, ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol),
             flow->src2dst_packets + flow->dst2src_packets + atoi(row[2]), flow->src2dst_bytes+flow->dst2src_bytes + atoi(row[3]),
             atoi(row[4]) + 1, atoi(row[0]));
    sql_query(text);

    printf("\npo updatu update\n");
}


