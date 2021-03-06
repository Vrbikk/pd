/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-17 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#ifdef WIN32
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>
#include <math.h>
#include "config.h"
#include "libndpi-2.1.0/libndpi/ndpi_api.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>
#include <stdbool.h>

#include "structs.h"
#include "tests.c"
#include "logger.h"
#include "db.h"

/** Client parameters **/
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path  */
static u_int8_t live_capture = 1;
static u_int8_t undetected_flows_deleted = 0;

const struct specific_proto specific_proto_default = {NULL, 0, false};
static struct specific_proto sp;

/** User preferences **/
static u_int8_t enable_protocol_guess = 1, verbose = 1, json_flag = 0;
static u_int8_t stats_flag = 0, bpf_filter_flag = 0;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
bool enable_mysql = false;
static u_int8_t num_threads = 1;
static struct timeval begin, end;
static int core_affinity[MAX_NUM_READER_THREADS];
static struct timeval pcap_start, pcap_end;
/** Detection parameters **/
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int32_t num_flows;

static pcap_dumper_t *extcap_dumper = NULL;
static char extcap_buf[16384];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;

// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;

bool is_valid_proto(struct specific_proto *sp, int protocol_number){
    for (int i = 0; i < sp->count; ++i) {

        int number = sp->protocols[i];
        if(number == protocol_number) {
            return true;
        }
    }
    return false;
}

void test_lib(); /* Forward */

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle);

/**
 * @brief Print help instructions
 */
static void help(u_int long_help) {
    printf("Welcome to nDPI %s\n\n", ndpi_revision());

    printf(             "Usage:\n"
                                " sudo ./pd -i enp0s25 -r (db config in config file)\n"
                                " sudo ./pd -i enp0s25 -w soubor.txt -v * (all protocols to file without db)\n"
                                "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a - needed for all usecases\n"
                                "  -r                        | enable mysql logging\n"
                                "  -w <path>                 | logging file for specific protocol flow detection with -v param \n"
                                "  -v                        | protocol number to log into file \\* for all or 1,2,3....\n");

    if (long_help) {
        printf("\n\nSupported protocols:\n");
        num_threads = 1;
        setupDetection(0, NULL);
        ndpi_dump_protocols(ndpi_thread_info[0].workflow->ndpi_struct);
    }
    exit(!long_help);
}

/* ********************************** */

int cmpFlows(const void *_a, const void *_b) {
    struct ndpi_flow_info *fa = ((struct flow_info*)_a)->flow;
    struct ndpi_flow_info *fb = ((struct flow_info*)_b)->flow;
    uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
    uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
    if(a_size != b_size)
        return a_size < b_size ? 1 : -1;

// copy from ndpi_workflow_node_cmp();

    if(fa->ip_version < fb->ip_version ) return(-1); else { if(fa->ip_version > fb->ip_version ) return(1); }
    if(fa->protocol   < fb->protocol   ) return(-1); else { if(fa->protocol   > fb->protocol   ) return(1); }
    if(htonl(fa->src_ip)   < htonl(fb->src_ip)  ) return(-1); else { if(htonl(fa->src_ip)   > htonl(fb->src_ip)  ) return(1); }
    if(htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if(htons(fa->src_port) > htons(fb->src_port)) return(1); }
    if(htonl(fa->dst_ip)   < htonl(fb->dst_ip)  ) return(-1); else { if(htonl(fa->dst_ip)   > htonl(fb->dst_ip)  ) return(1); }
    if(htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if(htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
    return(0);
}

/* ********************************** */

void extcap_capture() {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

    if((extcap_dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */),
                                       extcap_capture_fifo)) == NULL) {
        fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);

#ifdef DEBUG_TRACE
        if(trace) fprintf(trace, "Unable to open the pcap dumper on %s\n",
		      extcap_capture_fifo);
#endif
        return;
    }

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

/* ********************************** */

/**
 * @brief Option parser
 */
static void parseOptions(int argc, char **argv) {
    sp = specific_proto_default;
    int option_idx = 0, do_capture = 0;
    char *__pcap_file = NULL, *bind_mask = NULL;
    int thread_id, opt;
    u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

    while ((opt = getopt_long(argc, argv, "df:g:i:hp:l:s:tv:V:n:j:rp:w:q0123:456:7:89:m:b:x:", longopts, &option_idx)) != EOF) {

        switch (opt) {

            case 'i':
            case '3':
                _pcap_file[0] = optarg;
                break;


            case 'r':
               enable_mysql = true;
                break;
            case 'v':
                if(optarg != NULL){
                    set_specific_proto(&sp, optarg);
                }else{
                    help(0);
                }
                break;

            case 'w':
                setup_logger(optarg);
                break;

            default:
                help(0);
                break;
        }
    }

    if(!bpf_filter_flag) {
        if(do_capture) {
            quiet_mode = 1;
            extcap_capture();
        }

        // check parameters
        if(!bpf_filter_flag && (_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0)) {
            help(0);
        }

        if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
            num_threads = 0;               /* setting number of threads = number of interfaces */
            __pcap_file = strtok(_pcap_file[0], ",");
            while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
                _pcap_file[num_threads++] = __pcap_file;
                __pcap_file = strtok(NULL, ",");
            }
        } else {
            if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
            for(thread_id = 1; thread_id < num_threads; thread_id++)
                _pcap_file[thread_id] = _pcap_file[0];
        }

        for(thread_id = 0; thread_id < num_threads; thread_id++)
            core_affinity[thread_id] = -1;

        if(num_cores > 1 && bind_mask != NULL) {
            char *core_id = strtok(bind_mask, ":");
            thread_id = 0;
            while (core_id != NULL && thread_id < num_threads) {
                core_affinity[thread_id++] = atoi(core_id) % num_cores;
                core_id = strtok(NULL, ":");
            }
        }
    }


}

/**
 * @brief Print the flow
 */
static void printFlow(u_int16_t id, struct ndpi_flow_info *flow, u_int16_t thread_id) {
    FILE *out = results_file ? results_file : stdout;

    if((verbose != 1) && (verbose != 2))
        return;

    if(!json_flag) {
        fprintf(out, "\t%u", id);

        fprintf(out, "\t%s ", ipProto2Name(flow->protocol));

        fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
                (flow->ip_version == 6) ? "[" : "",
                flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
                flow->bidirectional ? "<->" : "->",
                (flow->ip_version == 6) ? "[" : "",
                flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
        );

        if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

        if(flow->detected_protocol.master_protocol) {
            char buf[64];

            fprintf(out, "[proto: %u.%u/%s]",
                    flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
                    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                       flow->detected_protocol, buf, sizeof(buf)));
        } else
            fprintf(out, "[proto: %u/%s]",
                    flow->detected_protocol.app_protocol,
                    ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct, flow->detected_protocol.app_protocol));

        fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
        fprintf(out, "%s %u pkts/%llu bytes]",
                (flow->dst2src_packets > 0) ? "<->" : "->",
                flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

        if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
        if(flow->info[0] != '\0') fprintf(out, "[%s]", flow->info);

        if(flow->ssh_ssl.client_info[0] != '\0') fprintf(out, "[client: %s]", flow->ssh_ssl.client_info);
        if(flow->ssh_ssl.server_info[0] != '\0') fprintf(out, "[server: %s]", flow->ssh_ssl.server_info);
        if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

        fprintf(out, "\n");
    }
}

/**
 * @brief Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);

    if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
        num_flows++;
    }
}

/**
 * @brief Known Proto Walker
 */
static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);

    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
        num_flows++;
    }
}


/**
 * @brief Guess Undetected Protocol
 */
static u_int16_t node_guess_undetected_protocol(u_int16_t thread_id, struct ndpi_flow_info *flow) {

    flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                                             flow->protocol,
                                                             ntohl(flow->src_ip),
                                                             ntohs(flow->src_port),
                                                             ntohl(flow->dst_ip),
                                                             ntohs(flow->dst_port));
    // printf("Guess state: %u\n", flow->detected_protocol);
    if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;

    return(flow->detected_protocol.app_protocol);
}

/**
 * @brief Proto Guess Walker
 */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if((!flow->detection_completed) && flow->ndpi_flow)
            flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct, flow->ndpi_flow);

        if(enable_protocol_guess) {
            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
                node_guess_undetected_protocol(thread_id, flow);
            }
        }

        process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);
        ndpi_thread_info[thread_id].workflow->stats.protocol_counter[flow->detected_protocol.app_protocol]       += flow->src2dst_packets + flow->dst2src_packets;
        ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[flow->detected_protocol.app_protocol] += flow->src2dst_bytes + flow->dst2src_bytes;
        ndpi_thread_info[thread_id].workflow->stats.protocol_flows[flow->detected_protocol.app_protocol]++;

        //printf("%d - %d\n",jej++, flow->detected_protocol.app_protocol);

    }
}

/* *********************************************** */

void updateScanners(struct single_flow_info **scanners, u_int32_t saddr,
                    u_int8_t version, u_int32_t dport) {
    struct single_flow_info *f;
    struct port_flow_info *p;

    HASH_FIND_INT(*scanners, (int *)&saddr, f);

    if(f == NULL) {
        f = (struct single_flow_info*)malloc(sizeof(struct single_flow_info));
        if(!f) return;
        f->saddr = saddr;
        f->version = version;
        f->tot_flows = 1;
        f->ports = NULL;

        p = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));

        if(!p) {
            free(f);
            return;
        } else
            p->port = dport, p->num_flows = 1;

        HASH_ADD_INT(f->ports, port, p);
        HASH_ADD_INT(*scanners, saddr, f);
    } else{
        struct port_flow_info *pp;
        f->tot_flows++;

        HASH_FIND_INT(f->ports, (int *)&dport, pp);

        if(pp == NULL) {
            pp = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));
            if(!pp) return;
            pp->port = dport, pp->num_flows = 1;

            HASH_ADD_INT(f->ports, port, pp);
        } else
            pp->num_flows++;
    }
}

/* *********************************************** */

int updateIpTree(u_int32_t key, u_int8_t version,
                 addr_node **vrootp, const char *proto) {
    addr_node *q;
    addr_node **rootp = vrootp;

    if(rootp == (addr_node **)0)
        return 0;

    while (*rootp != (addr_node *)0) {
        /* Knuth's T1: */
        if((version == (*rootp)->version) && (key == (*rootp)->addr)) {
            /* T2: */
            return ++((*rootp)->count);
        }

        rootp = (key < (*rootp)->addr) ?
                &(*rootp)->left :		/* T3: follow left branch */
                &(*rootp)->right;		/* T4: follow right branch */
    }

    q = (addr_node *) malloc(sizeof(addr_node));	/* T5: key not found */
    if(q != (addr_node *)0) {	                /* make new node */
        *rootp = q;			                /* link new node to old */

        q->addr = key;
        q->version = version;
        strncpy(q->proto, proto, sizeof(q->proto));
        q->count = UPDATED_TREE;
        q->left = q->right = (addr_node *)0;

        return q->count;
    }

    return(0);
}
/* *********************************************** */

void freeIpTree(addr_node *root) {
    if (root == NULL)
        return;

    freeIpTree(root->left);
    freeIpTree(root->right);
    free(root);
    root = NULL;
}

/* *********************************************** */

void updateTopIpAddress(u_int32_t addr, u_int8_t version, const char *proto,
                        int count, struct info_pair top[], int size) {
    struct info_pair pair;
    int min = count;
    int update = 0;
    int min_i = 0;
    int r;
    int i;

    if(count == 0) return;

    pair.addr = addr;
    pair.version = version;
    pair.count = count;
    strncpy(pair.proto, proto, sizeof(pair.proto));

    for(i=0; i<size; i++) {
        /* if the same ip with a bigger
           count just update it     */
        if(top[i].addr == addr) {
            top[i].count = count;
            return;
        }
        /* if array is not full yet
           add it to the first empty place */
        if(top[i].count == 0) {
            top[i] = pair;
            return;
        }
    }

    /* if bigger than the smallest one, replace it */
    for(i=0; i<size; i++) {
        if(top[i].count < count && top[i].count < min) {
            min = top[i].count;
            min_i = i;
            update = 1;
        }
    }

    if(update)
        top[min_i] = pair;
}

/* *********************************************** */

static void updatePortStats(struct port_stats **stats, u_int32_t port,
                            u_int32_t addr, u_int8_t version,
                            u_int32_t num_pkts, u_int32_t num_bytes,
                            const char *proto) {

    struct port_stats *s = NULL;
    int count = 0;

    HASH_FIND_INT(*stats, &port, s);
    if(s == NULL) {
        s = (struct port_stats*)calloc(1, sizeof(struct port_stats));
        if(!s) return;

        s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
        s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

        updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

        s->addr_tree = (addr_node *) malloc(sizeof(addr_node));
        if(!s->addr_tree) {
            free(s);
            return;
        }

        s->addr_tree->addr = addr;
        s->addr_tree->version = version;
        strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto));
        s->addr_tree->count = 1;
        s->addr_tree->left = NULL;
        s->addr_tree->right = NULL;

        HASH_ADD_INT(*stats, port, s);
    }
    else{
        count = updateIpTree(addr, version, &(*s).addr_tree, proto);

        if(count == UPDATED_TREE) s->num_addr++;

        if(count) {
            s->cumulative_addr++;
            updateTopIpAddress(addr, version, proto, count, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);
        }

        s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
    }
}

/* *********************************************** */

/* @brief heuristic choice for receiver stats */
static int acceptable(u_int32_t num_pkts){
    return num_pkts > 5;
}

/* *********************************************** */

static int receivers_sort_asc(void *_a, void *_b) {
    struct receiver *a = (struct receiver *)_a;
    struct receiver *b = (struct receiver *)_b;

    return(a->num_pkts - b->num_pkts);
}

/* ***************************************************** */
/*@brief removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
*/
static struct receiver *cutBackTo(struct receiver **receivers, u_int32_t size, u_int32_t max) {
    struct receiver *r, *tmp;
    int i=0;
    int count;

    if(size < max) //return the original table
        return *receivers;

    count = size - max;

    HASH_ITER(hh, *receivers, r, tmp) {
        if(i++ == count)
            return r;
        HASH_DEL(*receivers, r);
        free(r);
    }
}

/* *********************************************** */
/*@brief merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
*/
static void mergeTables(struct receiver **primary, struct receiver **secondary) {
    struct receiver *r, *s, *tmp;

    HASH_ITER(hh, *primary, r, tmp) {
        HASH_FIND_INT(*secondary, (int *)&(r->addr), s);
        if(s == NULL){
            s = (struct receiver *)malloc(sizeof(struct receiver));
            if(!s) return;

            s->addr = r->addr;
            s->version = r->version;
            s->num_pkts = r->num_pkts;

            HASH_ADD_INT(*secondary, addr, s);
        }
        else
            s->num_pkts += r->num_pkts;

        HASH_DEL(*primary, r);
        free(r);
    }
}
/* *********************************************** */

static void deleteReceivers(struct receiver *receivers) {
    struct receiver *current, *tmp;

    HASH_ITER(hh, receivers, current, tmp) {
        HASH_DEL(receivers, current);
        free(current);
    }
}

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if (table1.size < max1 || acceptable){
 *    create new element and add to the table1
 *    if (table1.size > max2) {
 *      cut table1 back to max1
 *      merge table 1 to table2
 *      if(table2.size > max1)
 *        cut table2 back to max1
 *    }
 * }
 * else
 *   update table1
*/
static void updateReceivers(struct receiver **receivers, u_int32_t dst_addr,
                            u_int8_t version, u_int32_t num_pkts,
                            struct receiver **topReceivers) {
    struct receiver *r;
    u_int32_t size;
    int a;

    HASH_FIND_INT(*receivers, (int *)&dst_addr, r);
    if(r == NULL) {
        if(((size = HASH_COUNT(*receivers)) < MAX_TABLE_SIZE_1)
           || ((a = acceptable(num_pkts)) != 0)){
            r = (struct receiver *)malloc(sizeof(struct receiver));
            if(!r) return;

            r->addr = dst_addr;
            r->version = version;
            r->num_pkts = num_pkts;

            HASH_ADD_INT(*receivers, addr, r);

            if((size = HASH_COUNT(*receivers)) > MAX_TABLE_SIZE_2){

                HASH_SORT(*receivers, receivers_sort_asc);
                *receivers = cutBackTo(receivers, size, MAX_TABLE_SIZE_1);
                mergeTables(receivers, topReceivers);

                if((size = HASH_COUNT(*topReceivers)) > MAX_TABLE_SIZE_1){
                    HASH_SORT(*topReceivers, receivers_sort_asc);
                    *topReceivers = cutBackTo(topReceivers, size, MAX_TABLE_SIZE_1);
                }

                *receivers = NULL;
            }
        }
    }
    else
        r->num_pkts += num_pkts;
}

static void deleteScanners(struct single_flow_info *scanners) {
    struct single_flow_info *s, *tmp;
    struct port_flow_info *p, *tmp2;

    HASH_ITER(hh, scanners, s, tmp) {
        HASH_ITER(hh, s->ports, p, tmp2) {
            HASH_DEL(s->ports, p);
            free(p);
        }
        HASH_DEL(scanners, s);
        free(s);
    }
}

/* *********************************************** */

static void deletePortsStats(struct port_stats *stats) {
    struct port_stats *current_port, *tmp;

    HASH_ITER(hh, stats, current_port, tmp) {
        HASH_DEL(stats, current_port);
        freeIpTree(current_port->addr_tree);
        free(current_port);
    }
}

/* *********************************************** */

/**
 * @brief Ports stats
 */
static void port_stats_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
        u_int16_t thread_id = *(int *)user_data;
        u_int16_t sport, dport;
        char proto[16];
        int r;

        sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

        /* get app level protocol */
        if(flow->detected_protocol.master_protocol)
            ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                               flow->detected_protocol, proto, sizeof(proto));
        else
            strncpy(proto, ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                               flow->detected_protocol.app_protocol),sizeof(proto));

        if(((r = strcmp(ipProto2Name(flow->protocol), "TCP")) == 0)
           && (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0)) {
            updateScanners(&scannerHosts, flow->src_ip, flow->ip_version, dport);
        }

        updateReceivers(&receivers, flow->dst_ip, flow->ip_version,
                        flow->src2dst_packets, &topReceivers);

        updatePortStats(&srcStats, sport, flow->src_ip, flow->ip_version,
                        flow->src2dst_packets, flow->src2dst_bytes, proto);

        updatePortStats(&dstStats, dport, flow->dst_ip, flow->ip_version,
                        flow->dst2src_packets, flow->dst2src_bytes, proto);
    }
}

/* *********************************************** */

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);

    if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET)
        return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            ndpi_free_flow_info_half(flow);
            ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
        }
    }
}

/**
 * @brief On Protocol Discover - call node_guess_undetected_protocol() for protocol
 */
static void on_protocol_discovered(struct ndpi_workflow * workflow,
                                   struct ndpi_flow_info * flow,
                                   void * udata) {

    if(flow->ip_version == 6) return;

    const u_int16_t thread_id = (uintptr_t) udata;

    if(sp.all == true || is_valid_proto(&sp, flow->detected_protocol.app_protocol)){
        printFlow(0, flow, 0);

        if(logging_file != NULL) {
            logger(flow, ndpi_thread_info[thread_id].workflow->ndpi_struct);
        }

        if(enable_mysql) {

            /*if (ip_exists(flow->src_name, flow->detected_protocol.app_protocol,
                          ndpi_thread_info[thread_id].workflow->ndpi_struct)) {
                update_flow(flow, ndpi_thread_info[thread_id].workflow->ndpi_struct);
            } else {
                insert_flow(flow, ndpi_thread_info[thread_id].workflow->ndpi_struct);
            }*/

            if(src_ip_exists(flow)){
                update_host();
            }else{
                insert_host(flow);
            }

            if(protocol_exists(flow, ndpi_thread_info[thread_id].workflow->ndpi_struct)){
                update_protocol();
            }else{
                insert_protocol(flow, ndpi_thread_info[thread_id].workflow->ndpi_struct);
            }

            if(conn_exists(flow)){
                update_conn(flow);
            }else{
                insert_conn(flow);
            }
        }
    }
}

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle) {

    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_workflow_prefs prefs;

    memset(&prefs, 0, sizeof(prefs));
    prefs.decode_tunnels = decode_tunnels;
    prefs.num_roots = NUM_ROOTS;
    prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
    prefs.quiet_mode = quiet_mode;

    memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
    ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle);

    /* Preferences */
    ndpi_thread_info[thread_id].workflow->ndpi_struct->http_dont_dissect_response = 0;
    ndpi_thread_info[thread_id].workflow->ndpi_struct->dns_dissect_response = 0;

    ndpi_workflow_set_flow_detected_callback(ndpi_thread_info[thread_id].workflow,
                                             on_protocol_discovered, (void *)(uintptr_t)thread_id);

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

    // clear memory for results
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

    if(_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);
}


/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
    ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
}


/**
 * @brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char *buf) {

    char unit;

    if(bits)
        unit = 'b';
    else
        unit = 'B';

    if(numBits < 1024) {
        snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
    } else if(numBits < (1024*1024)) {
        snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
    } else {
        float tmpMBits = ((float)numBits)/(1024*1024);

        if(tmpMBits < 1024) {
            snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        } else {
            tmpMBits /= 1024;

            if(tmpMBits < 1024) {
                snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            } else {
                snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
            }
        }
    }

    return(buf);
}


/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

    if(numPkts < 1000) {
        snprintf(buf, 32, "%.2f", numPkts);
    } else if(numPkts < (1000*1000)) {
        snprintf(buf, 32, "%.2f K", numPkts/1000);
    } else {
        numPkts /= (1000*1000);
        snprintf(buf, 32, "%.2f M", numPkts);
    }

    return(buf);
}

/* *********************************************** */

/**
 * @brief Bytes stats format
 */
char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
    char unit = 'B';

    if(howMuch < 1024) {
        snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
    } else if(howMuch < (1024*1024)) {
        snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
    } else {
        float tmpGB = ((float)howMuch)/(1024*1024);

        if(tmpGB < 1024) {
            snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
        } else {
            tmpGB /= 1024;

            snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
        }
    }

    return(buf);
}

/* *********************************************** */

static int port_stats_sort(void *_a, void *_b) {
    struct port_stats *a = (struct port_stats*)_a;
    struct port_stats *b = (struct port_stats*)_b;

    if(b->num_pkts == 0 && a->num_pkts == 0)
        return(b->num_flows - a->num_flows);

    return(b->num_pkts - a->num_pkts);
}

/* *********************************************** */

static int info_pair_cmp (const void *_a, const void *_b)
{
    struct info_pair *a = (struct info_pair *)_a;
    struct info_pair *b = (struct info_pair *)_b;

    return b->count - a->count;
}

/* *********************************************** */

void printPortStats(struct port_stats *stats) {
    struct port_stats *s, *tmp;
    char addr_name[48];
    int i = 0, j = 0;

    HASH_ITER(hh, stats, s, tmp) {
        i++;
        printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
               i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

        qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

        for(j=0; j<MAX_NUM_IP_ADDRESS; j++) {
            if(s->top_ip_addrs[j].count != 0) {
                if(s->top_ip_addrs[j].version == IPVERSION) {
                    inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
                } else {
                    inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr),  addr_name, sizeof(addr_name));
                }

                printf("\t\t%-36s ~ %.2f%%\n", addr_name,
                       ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
            }
        }

        printf("\n");
        if(i >= 10) break;
    }
}


/* *********************************************** */

/**
 * @brief Print result
 */
static void printResults(u_int64_t tot_usec) {
    u_int32_t i;
    u_int64_t total_flow_bytes = 0;
    u_int32_t avg_pkt_size = 0;
    struct ndpi_stats cumulative_stats;
    int thread_id;
    char buf[32];
    long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

    memset(&cumulative_stats, 0, sizeof(cumulative_stats));

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        if((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
           && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
            continue;

        printf("\n ---- %d\n",ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[37]);


        for(i=0; i<NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], node_proto_guess_walker, &thread_id);
            if(verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], port_stats_walker, &thread_id);
        }

        printf("\n ---- %d\n",ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[37]);


        /* Stats aggregation */
        cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
        cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
        cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
        cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
        cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
        cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

        for(i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
            cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
            cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
            cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];
        }

        cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
        cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
        cumulative_stats.udp_count   += ndpi_thread_info[thread_id].workflow->stats.udp_count;
        cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
        cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
        cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
        cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
        for(i = 0; i < sizeof(cumulative_stats.packet_len)/sizeof(cumulative_stats.packet_len[0]); i++)
            cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
        cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;
    }

    if(cumulative_stats.total_wire_bytes == 0)
        goto free_stats;

    if(!quiet_mode) {
        printf("\nnDPI Memory statistics:\n");
        printf("\tnDPI Memory (once):      %-13s\n", formatBytes(sizeof(struct ndpi_detection_module_struct), buf, sizeof(buf)));
        printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(sizeof(struct ndpi_flow_struct), buf, sizeof(buf)));
        printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
        printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));

        if(!json_flag) {
            printf("\nTraffic statistics:\n");
            printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
                   (long long unsigned int)cumulative_stats.total_wire_bytes);
            printf("\tDiscarded bytes:       %-13llu\n",
                   (long long unsigned int)cumulative_stats.total_discarded_bytes);
            printf("\tIP packets:            %-13llu of %llu packets total\n",
                   (long long unsigned int)cumulative_stats.ip_packet_count,
                   (long long unsigned int)cumulative_stats.raw_packet_count);
            /* In order to prevent Floating point exception in case of no traffic*/
            if(cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
                avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
            printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
                   (long long unsigned int)cumulative_stats.total_ip_bytes,avg_pkt_size);
            printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);

            printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
            printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
            printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
            printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
            printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
            printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
            printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
            printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
            printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
            printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
            printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
            printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
            printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

            if(tot_usec > 0) {
                char buf[32], buf1[32], when[64];
                float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)tot_usec;
                float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)tot_usec;
                float traffic_duration;
                if(live_capture) traffic_duration = tot_usec;
                else traffic_duration = (pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - (pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
                printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
                t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
                b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;

                strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime(&pcap_start.tv_sec));
                printf("\tAnalysis begin:        %s\n", when);
                strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime(&pcap_end.tv_sec));
                printf("\tAnalysis end:          %s\n", when);
                printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
                printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
            }

            if(enable_protocol_guess)
                printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);
        }
    }

    if(!quiet_mode) printf("\n\nDetected protocols:\n");
    for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct, i);

        if(cumulative_stats.protocol_counter[i] > 0) {
            breed_stats[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];

            if(results_file)
                fprintf(results_file, "%s\t%llu\t%llu\t%u\n",
                        ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
                        (long long unsigned int)cumulative_stats.protocol_counter[i],
                        (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
                        cumulative_stats.protocol_flows[i]);

            if(!quiet_mode) {
                printf("[%d] \t%-20s packets: %-13llu bytes: %-13llu "
                               "flows: %-13u\n", i,
                       ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
                       (long long unsigned int)cumulative_stats.protocol_counter[i],
                       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
                       cumulative_stats.protocol_flows[i]);
            }

            total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
        }
    }

    if(!quiet_mode) {
        printf("\n\nProtocol statistics:\n");

        for(i=0; i < NUM_BREEDS; i++) {
            if(breed_stats[i] > 0) {
                printf("\t%-20s %13llu bytes\n",
                       ndpi_get_proto_breed_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
                       breed_stats[i]);
            }
        }
    }

    // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

    if((verbose == 2)) {
        FILE *out = results_file ? results_file : stdout;
        u_int32_t total_flows = 0;

        for (thread_id = 0; thread_id < num_threads; thread_id++)
            total_flows += ndpi_thread_info[thread_id].workflow->num_allocated_flows;

        if ((all_flows = (struct flow_info *) malloc(sizeof(struct flow_info) * total_flows)) == NULL) {
            printf("Fatal error: not enough memory\n");
            exit(-1);
        }

        if (!json_flag) fprintf(out, "\n");

        num_flows = 0;
        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            for (i = 0; i < NUM_ROOTS; i++)
                ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], node_print_known_proto_walker,
                           &thread_id);
        }

        qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

        for (i = 0; i < num_flows; i++)
            printFlow(i + 1, all_flows[i].flow, all_flows[i].thread_id);

        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            if (ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
                if (!json_flag) {
                    FILE *out = results_file ? results_file : stdout;

                    fprintf(out, "\n\nUndetected flows:%s\n",
                            undetected_flows_deleted ? " (expired flows are not listed below)" : "");
                }

                if (json_flag)
                    json_flag = 2;
                break;
            }
        }

        num_flows = 0;
        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            if (ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0) {
                for (i = 0; i < NUM_ROOTS; i++)
                    ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                               node_print_unknown_proto_walker, &thread_id);
            }
        }

        qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

        for (i = 0; i < num_flows; i++)
            printFlow(i + 1, all_flows[i].flow, all_flows[i].thread_id);

        free(all_flows);
    }

    if(stats_flag || verbose == 3) {
        HASH_SORT(srcStats, port_stats_sort);
        HASH_SORT(dstStats, port_stats_sort);
    }

    if(verbose == 3) {
        printf("\n\nSource Ports Stats:\n");
        printPortStats(srcStats);

        printf("\nDestination Ports Stats:\n");
        printPortStats(dstStats);
    }

    free_stats:
    if(scannerHosts) {
        deleteScanners(scannerHosts);
        scannerHosts = NULL;
    }

    if(receivers){
        deleteReceivers(receivers);
        receivers = NULL;
    }

    if(topReceivers){
        deleteReceivers(topReceivers);
        topReceivers = NULL;
    }

    if(srcStats) {
        deletePortsStats(srcStats);
        srcStats = NULL;
    }

    if(dstStats) {
        deletePortsStats(dstStats);
        dstStats = NULL;
    }
}

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
        pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
    }
}

/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig) {

    static int called = 0;
    int thread_id;

    if(called) return; else called = 1;
    shutdown_app = 1;

    for(thread_id=0; thread_id<num_threads; thread_id++)
        breakPcapLoop(thread_id);

    //fclose(log_ptr);
}


/**
 * @brief Get the next pcap file from a passed playlist
 */
static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {

    if(playlist_fp[thread_id] == NULL) {
        if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
            return -1;
    }

    next_line:
    if(fgets(filename, filename_len, playlist_fp[thread_id])) {
        int l = strlen(filename);
        if(filename[0] == '\0' || filename[0] == '#') goto next_line;
        if(filename[l-1] == '\n') filename[l-1] = '\0';
        return 0;
    } else {
        fclose(playlist_fp[thread_id]);
        playlist_fp[thread_id] = NULL;
        return -1;
    }
}


/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t * pcap_handle) {

    if(bpfFilter != NULL) {
        struct bpf_program fcode;

        if(pcap_compile(pcap_handle, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
            printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
        } else {
            if(pcap_setfilter(pcap_handle, &fcode) < 0) {
                printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
            } else
                printf("Successfully set BPF filter to '%s'\n", bpfFilter);
        }
    }
}


/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) {

    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t * pcap_handle = NULL;

    /* trying to open a live interface */
    if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen, promisc, 500, pcap_error_buffer)) == NULL) {
        capture_for = capture_until = 0;

        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */

        /* trying to open a pcap file */
        if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
            char filename[256];

            /* trying to open a pcap playlist */
            if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0 ||
               (pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL) {

                printf("ERROR: could not open pcap file or playlist: %s\n", pcap_error_buffer);
                exit(-1);
            } else {
                if(!quiet_mode) printf("Reading packets from playlist %s...\n", pcap_file);
            }
        } else {
            if(!quiet_mode) printf("Reading packets from pcap file %s...\n", pcap_file);
        }
    } else {
        live_capture = 1;

        if(!quiet_mode) printf("Capturing live traffic from device %s...\n", pcap_file);
    }

    configurePcapHandle(pcap_handle);

    if(capture_for > 0) {
        if(!quiet_mode) printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);
    }

    return pcap_handle;
}

/**
 * @brief Check pcap packet
 */
static void pcap_process_packet(u_char *args,
                                const struct pcap_pkthdr *header,
                                const u_char *packet) {

    struct ndpi_proto p;
    u_int16_t thread_id = *((u_int16_t*)args);

    /* allocate an exact size buffer to check overflows */
    uint8_t *packet_checked = malloc(header->caplen);

    memcpy(packet_checked, packet, header->caplen);
    p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked);

    //printResults(0);
    //printf("%d \n", ndpi_thread_info[thread_id].workflow->num_allocated_flows);

    //ndpi_thread_info[thread_id].workflow->stats.protocol_counter

    if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
        if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
        return;
    }

    /* Check if capture is live or not */
    if(!live_capture) {
        if(!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
        pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;
    }

    /* Idle flows cleanup */
    if(live_capture) {
        if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time) {
            /* scan for idle flows */
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

            /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_thread_info[thread_id].num_idle_flows > 0) {

                /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
                ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
                             &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
                             ndpi_workflow_node_cmp);

                /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
                ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
                ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
            }

            if(++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots) ndpi_thread_info[thread_id].idle_scan_idx = 0;
            ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
        }
    }

    if(extcap_dumper && ((extcap_packet_filter == (u_int16_t)-1)
                         || (p.app_protocol == extcap_packet_filter)
                         || (p.master_protocol == extcap_packet_filter)
    )
            ) {
        struct pcap_pkthdr h;
        uint32_t *crc, delta = sizeof(struct ndpi_packet_trailer) + 4 /* ethernet trailer */;
        struct ndpi_packet_trailer *trailer;

        memcpy(&h, header, sizeof(h));

        if(h.caplen > (sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4)) {
            printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
            h.caplen = sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4;
        }

        trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
        memcpy(extcap_buf, packet, h.caplen);
        memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
        trailer->magic = htonl(0x19680924);
        trailer->master_protocol = htons(p.master_protocol), trailer->app_protocol = htons(p.app_protocol);
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));
        crc = (uint32_t*)&extcap_buf[h.caplen+sizeof(struct ndpi_packet_trailer)];
        *crc = ethernet_crc32((const void*)extcap_buf, h.caplen+sizeof(struct ndpi_packet_trailer));
        h.caplen += delta;
        h.len += delta;

        pcap_dump((u_char*)extcap_dumper, &h, (const u_char *)extcap_buf);
        pcap_dump_flush(extcap_dumper);
    }

    /* check for buffer changes */
    if(memcmp(packet, packet_checked, header->caplen) != 0)
        printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
               thread_id, (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, header->caplen);
    free(packet_checked);

    if((pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
        int i;
        u_int64_t tot_usec;

        gettimeofday(&end, NULL);
        tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

        printResults(tot_usec);

        for(i=0; i<ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
            ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
            ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

            memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
        }

        printf("\n-------------------------------------------\n\n");

        memcpy(&begin, &end, sizeof(begin));
        memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
    }
}

/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
    if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
        pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &pcap_process_packet, (u_char*)&thread_id);
}

/**
 * @brief Process a running thread
 */
void * processing_thread(void *_thread_id) {

    long thread_id = (long) _thread_id;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    if(core_affinity[thread_id] >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_affinity[thread_id], &cpuset);

        if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
            fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
        else {
            if(!quiet_mode) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
        }
    } else

    if(!quiet_mode) printf("Running thread %ld...\n", thread_id);

    pcap_loop:
    runPcapLoop(thread_id);

    if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
        char filename[256];

        if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
           (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
            configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
            goto pcap_loop;
        }
    }
    return NULL;
}

/**
 * @brief Begin, process, end detection process
 */
void test_lib() {
    struct timeval end;
    u_int64_t tot_usec;
    long thread_id;

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t *cap;
        cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
        setupDetection(thread_id, cap);
    }

    gettimeofday(&begin, NULL);

    int status;
    void * thd_res;

    /* Running processing threads */
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
        /* check pthreade_create return value */
        if(status != 0) {
            fprintf(stderr, "error on create %ld thread\n", thread_id);
            exit(-1);
        }
    }

    /* Waiting for completion */
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
        /* check pthreade_join return value */
        if(status != 0) {
            fprintf(stderr, "error on join %ld thread\n", thread_id);
            exit(-1);
        }
        if(thd_res != NULL) {
            fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
            exit(-1);
        }
    }

    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

    /* Printing cumulative results */
    printResults(tot_usec);

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

        terminateDetection(thread_id);
    }
}

/**
   @brief MAIN FUNCTION
**/
int main(int argc, char **argv) {

    int i;

    automataUnitTest();
    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
    parseOptions(argc, argv);

    if(enable_mysql) init_conn(&sp);

    if(!quiet_mode) {
        printf("\n nDPI started \n");
        printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
    }

    signal(SIGINT, sigproc);

    for(i=0; i<num_loops; i++)
        test_lib();

    if(results_path)  free(results_path);
    if(results_file)  fclose(results_file);
    if(extcap_dumper) pcap_dump_close(extcap_dumper);

    if(enable_mysql) close_conn();

    return 0;
}