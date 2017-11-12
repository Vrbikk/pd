//
// Created by vrbik on 5.11.17.
//

#include "ndpi_util.h"
#include "uthash.h"

#ifndef PD_STRUCTS_H
#define PD_STRUCTS_H

struct flow_info {
    struct ndpi_flow_info *flow;
    u_int16_t thread_id;
};

static struct flow_info *all_flows;


struct info_pair {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16]; /*app level protocol*/
    int count;
};

typedef struct node_a{
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16]; /*app level protocol*/
    int count;
    struct node_a *left, *right;
}addr_node;

struct port_stats {
    u_int32_t port; /* we'll use this field as the key */
    u_int32_t num_pkts, num_bytes;
    u_int32_t num_flows;
    u_int32_t num_addr; /*number of distinct IP addresses */
    u_int32_t cumulative_addr; /*cumulative some of IP addresses */
    addr_node *addr_tree; /* tree of distinct IP addresses */
    struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
    u_int8_t hasTopHost; /* as boolean flag*/
    u_int32_t top_host; /*host that is contributed to > 95% of traffic*/
    u_int8_t version; /* top host's ip version */
    char proto[16]; /*application level protocol of top host */
    UT_hash_handle hh; /* makes this structure hashable */
};

struct port_stats *srcStats = NULL, *dstStats = NULL;


// struct to hold count of flows received by destination ports
struct port_flow_info {
    u_int32_t port; /* key */
    u_int32_t num_flows;
    UT_hash_handle hh;
};

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
    u_int32_t saddr; /* key */
    u_int8_t version; /* IP version */
    struct port_flow_info *ports;
    u_int32_t tot_flows;
    UT_hash_handle hh;
};

struct single_flow_info *scannerHosts = NULL;

// struct to hold top receiver hosts
struct receiver {
    u_int32_t addr; /* key */
    u_int8_t version; /* IP version */
    u_int32_t num_pkts;
    UT_hash_handle hh;
};

struct receiver *receivers = NULL, *topReceivers = NULL;


struct ndpi_packet_trailer {
    u_int32_t magic; /* 0x19682017 */
    u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
    char name[16];
};

// struct associated to a workflow for a thread
struct reader_thread {
    struct ndpi_workflow *workflow;
    pthread_t pthread;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

// array for every thread created for a flow
static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

// ID tracking
typedef struct ndpi_id {
    u_int8_t ip[4];		   // Ip address
    struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

static struct option longopts[] = {
        /* mandatory extcap options */
        { "extcap-interfaces", no_argument, NULL, '0'},
        { "extcap-version", optional_argument, NULL, '1'},
        { "extcap-dlts", no_argument, NULL, '2'},
        { "extcap-interface", required_argument, NULL, '3'},
        { "extcap-config", no_argument, NULL, '4'},
        { "capture", no_argument, NULL, '5'},
        { "extcap-capture-filter", required_argument, NULL, '6'},
        { "fifo", required_argument, NULL, '7'},
        { "debug", optional_argument, NULL, '8'},
        { "ndpi-proto-filter", required_argument, NULL, '9'},

        /* ndpiReader options */
        { "enable-protocol-guess", no_argument, NULL, 'd'},
        { "interface", required_argument, NULL, 'i'},
        { "filter", required_argument, NULL, 'f'},
        { "cpu-bind", required_argument, NULL, 'g'},
        { "loops", required_argument, NULL, 'l'},
        { "num-threads", required_argument, NULL, 'n'},

        { "protos", required_argument, NULL, 'p'},
        { "capture-duration", required_argument, NULL, 's'},
        { "decode-tunnels", no_argument, NULL, 't'},
        { "revision", no_argument, NULL, 'r'},
        { "verbose", no_argument, NULL, 'v'},
        { "version", no_argument, NULL, 'V'},
        { "help", no_argument, NULL, 'h'},
        { "json", required_argument, NULL, 'j'},
        { "result-path", required_argument, NULL, 'w'},
        { "quiet", no_argument, NULL, 'q'},

        {0, 0, 0, 0}
};


struct specific_proto{
    int *protocols;
    unsigned char count;
    bool all;
} specific_proto_default = {NULL, 0, false};

#endif //PD_STRUCTS_H
