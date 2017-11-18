//
// Created by vrbik on 17.11.17.
//

#include "db.h"

char *server = "localhost";
char *user = "pd";
char *password = "pd";
char *database = "pd";


bool ip_exists(const char *ip){
    char target[150];
    snprintf( target, sizeof(target), "%s%s%s", "select * from proto_37 WHERE src_ip=\"", ip, "\"");
    mysql_free_result(res);
    res = sql_query(target);
    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

MYSQL_RES *sql_query(const char *query){
    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }
    return mysql_use_result(conn);
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

    /*if(ip_exists("10.0.0.5")){
        printf("je tam");
    }else{
        printf("prazdny");
    }*/


    /*while ((row = mysql_fetch_row(res)) != NULL)
        printf("%s \n", row[1]);*/


}

void insert_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){
    char target[200];
    snprintf(target, sizeof(target), "insert into proto_37 (src_ip, pkts, kbytes, flows) VALUES (\"%s\",%d,%d,%d)",
    flow->src_name, flow->src2dst_packets + flow->dst2src_packets, (flow->src2dst_bytes+flow->dst2src_bytes)/8, 1);
    sql_query(target);

    printf("\npo insertu\n");

}

void update_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){
    printf("\nupdate\n");
}


