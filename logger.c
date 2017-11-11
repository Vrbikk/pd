//
// Created by vrbik on 11.11.17.
//


#include "logger.h"

void setup_logger(const char *file){
    logging_file = file;
    FILE *fptr;
    fptr = fopen(logging_file, "rb+");
    if(fptr == NULL){
        fopen(logging_file, "wb");
        fclose(fptr);
    }
}

void logger(struct ndpi_flow_info *flow, struct ndpi_detection_module_struct *ndpi_struct){

    if(log_ptr == NULL) log_ptr = fopen(logging_file, "a+");

    time_t rawtime;
    struct tm * timeinfo;
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* time = asctime(timeinfo);
    time[strlen(time) - 1] = 0;
    fprintf(log_ptr, "[%s] - ", time);

    fprintf(log_ptr, "%s ", ipProto2Name(flow->protocol));

        fprintf(log_ptr, "%s%s%s:%u %s %s%s%s:%u ",
                (flow->ip_version == 6) ? "[" : "",
                flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
                flow->bidirectional ? "<->" : "->",
                (flow->ip_version == 6) ? "[" : "",
                flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
        );

        if(flow->vlan_id > 0) fprintf(log_ptr, "[VLAN: %u]", flow->vlan_id);

        if(flow->detected_protocol.master_protocol) {
            char buf[64];

            fprintf(log_ptr, "[proto: %u.%u/%s]",
                    flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
                    ndpi_protocol2name(ndpi_struct,
                                       flow->detected_protocol, buf, sizeof(buf)));
        } else
            fprintf(log_ptr, "[proto: %u/%s]",
                    flow->detected_protocol.app_protocol,
                    ndpi_get_proto_name(ndpi_struct, flow->detected_protocol.app_protocol));

        fprintf(log_ptr, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
        fprintf(log_ptr, "%s %u pkts/%llu bytes]",
                (flow->dst2src_packets > 0) ? "<->" : "->",
                flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

        if(flow->host_server_name[0] != '\0') fprintf(log_ptr, "[Host: %s]", flow->host_server_name);
        if(flow->info[0] != '\0') fprintf(log_ptr, "[%s]", flow->info);

        if(flow->ssh_ssl.client_info[0] != '\0') fprintf(log_ptr, "[client: %s]", flow->ssh_ssl.client_info);
        if(flow->ssh_ssl.server_info[0] != '\0') fprintf(log_ptr, "[server: %s]", flow->ssh_ssl.server_info);
        if(flow->bittorent_hash[0] != '\0') fprintf(log_ptr, "[BT Hash: %s]", flow->bittorent_hash);

        fprintf(log_ptr, "\n");

}


