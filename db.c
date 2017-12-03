//
// Created by vrbik on 17.11.17.
//

#include "db.h"



char *config[5];

/*char *server = NULL;
char *user = NULL;
char *password = NULL;
char *database = NULL;*/

void set_specific_proto(struct specific_proto *sp, const char *arg){
    if(arg[0] == '*'){
        sp->all = true;
        return;
    }

    u_int8_t count = 1;
    for (int i = 0; i < strlen(arg); ++i) {
        if(arg[i] == ',') count++;
    }

    sp->count = count;
    sp->protocols = malloc(count * sizeof(int));

    char * pch;
    pch = strtok (arg,",");
    int i = 0;
    while (pch != NULL)
    {
        *(sp->protocols + i++) = atoi(pch);
        pch = strtok (NULL, ",");
    }
}

void parse_config(struct specific_proto *sp){
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("config", "r");
    if (fp == NULL) {
        printf("failed to open mysql config");
        exit(0);
    }

    int i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {

        if(read < 5){
            printf("bad config file");
            exit(0);
        }

        for(int j = 0; j < read; j++){
            if(line[j] == ':'){
                config[i] = malloc((read - j - 1) * sizeof(char));
                memcpy( config[i], &line[j + 1], read - j);
                config[i][read - j - 2] = '\0';
                printf("%s", config[i]);
                break;
            }
        }

        i++;
    }

    fclose(fp);
    set_specific_proto(sp, config[4]);
    if (line) free(line);
}

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


/**
 * from https://www.lemoda.net/c/ip-to-integer/
 * @param ip
 * @return
 */
unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
                /* We insist on stopping at "." if we are still parsing
                   the first, second, or third numbers. If we have reached
                   the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return 0;
            }
        }
        if (n >= 256) {
            return 0;
        }
        v *= 256;
        v += n;
    }
    return v;
}


bool ip_exists(const char *ip, int id, struct ndpi_detection_module_struct *ndpi_struct){
    char text[150];
    snprintf( text, sizeof(text), "select * from proto_%d_%s WHERE src_ip=\"%s\"", id, ndpi_get_proto_name(ndpi_struct, id), ip);
    sql_query(text);

    if(mysql_errno(conn) == 1146){ //table not found
        create_table_protocol(id, ndpi_get_proto_name(ndpi_struct, id));
        return false;
    }

    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

void sql_query(const char *query){
    mysql_free_result(res);
    if (mysql_query(conn, query) && (mysql_errno(conn) != 1146)) { // 1146 = table not found
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }
    res = mysql_use_result(conn);
}

void close_conn(){
    mysql_close(conn);

    for(int i = 0; i < 4; i++){
        free(config[i]);
    }
}

void init_conn(struct specific_proto *sp){
    conn = mysql_init(NULL);

    parse_config(sp);

    if (!mysql_real_connect(conn, config[0], config[1], config[2], config[3], 0, NULL, 0)) {
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
}

void update_flow(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){

    char text[200];
    snprintf(text, sizeof(text), "UPDATE proto_%d_%s set pkts=%d, bytes=%d, flows=%d, last=now() WHERE id=%d",
             flow->detected_protocol.app_protocol, ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol),
             flow->src2dst_packets + flow->dst2src_packets + atoi(row[2]), flow->src2dst_bytes+flow->dst2src_bytes + atoi(row[3]),
             atoi(row[4]) + 1, atoi(row[0]));
    sql_query(text);
}


int last_insert_id(){
    sql_query("SELECT LAST_INSERT_ID()");
    row = mysql_fetch_row(res);
    return atoi(row[0]);
}


bool src_ip_exists(struct ndpi_flow_info *flow){
    char text[100];
    snprintf(text, sizeof(text), "select id from hosts where ip=%u", ip_to_int(flow->src_name));
    sql_query(text);
    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

void insert_host(struct ndpi_flow_info *flow){
    char text[300];
    snprintf(text, sizeof(text), "insert into hosts (log_id, ip, hostname, last_active_at) values (%u, %u, \"%s\", CURRENT_TIMESTAMP)",
                                    1, ip_to_int(flow->src_name), flow->src_name);
    sql_query(text);
    host_id = last_insert_id();
}

void update_host(){
    char text[200];
    snprintf(text, sizeof(text), "update hosts set last_active_at=CURRENT_TIMESTAMP where id=%u",
             atoi(row[0]));
    host_id = atoi(row[0]);
    sql_query(text);
}

bool protocol_exists(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){
    char text[300];
    snprintf(text, sizeof(text), "select id from protocols where host_id=%u and protocol=\"%s_%d\"",
             host_id,
             ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol),
             flow->detected_protocol.app_protocol);
    sql_query(text);
    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

void insert_protocol(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){
    char text[300];
    snprintf(text, sizeof(text), "insert into protocols (host_id, protocol, detected_at, last_active_at) values (%u, \"%s_%d\", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
             host_id, ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol),
             flow->detected_protocol.app_protocol);
    sql_query(text);
    protocol_id = last_insert_id();
}

void update_protocol(){
    char text[200];
    snprintf(text, sizeof(text), "update protocols set last_active_at=CURRENT_TIMESTAMP where id=%u",
             atoi(row[0]));
    protocol_id = atoi(row[0]);
    sql_query(text);
}

bool conn_exists(struct ndpi_flow_info *flow){
    char text[400];
    snprintf(text, sizeof(text), "select id, packets_in, packets_out from connections where protocol_id=%u and local_port=%u and remote_ip=%u and remote_port=%u",
             protocol_id, ntohs(flow->src_port), ip_to_int(flow->dst_name), ntohs(flow->dst_port));
    sql_query(text);
    return ((row = mysql_fetch_row(res)) != NULL) ? true : false;
}

void insert_conn(struct ndpi_flow_info *flow){
    char text[600];
    snprintf(text, sizeof(text), "insert into connections (protocol_id, local_port, remote_ip, remote_port, detected_at, last_active_at, packets_in, packets_out) values (%u, %u, %u, %u, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %d, %d)",
             protocol_id, ntohs(flow->src_port), ip_to_int(flow->dst_name), ntohs(flow->dst_port), flow->dst2src_packets, flow->src2dst_packets);
    sql_query(text);
}

void update_conn(struct ndpi_flow_info *flow){
    char text[300];
    snprintf(text, sizeof(text), "update connections set packets_in=%u, packets_out=%u, last_active_at=CURRENT_TIMESTAMP where id=%u",
             atoi(row[1]) + flow->dst2src_packets, atoi(row[2]) + flow->src2dst_packets, atoi(row[0]));
    sql_query(text);
}





