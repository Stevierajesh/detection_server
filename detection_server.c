/**
 * @file detection_server.c
 * @brief Detection server implementation for the Canopy project.
 */

/* 1. Preprocessor Directives */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>

/* 2. Constants and Global Variables */
#define RX_RING_SIZE 512
#define BURST_SIZE 32
#define MAX_FLOWS 10000

#define PACKET_RATE_THRESHOLD 10000  // packets per second
#define BYTE_RATE_THRESHOLD 100000000  // bytes per second (100 Mbps)
#define FLOW_DURATION_MIN 100000  // min cycles for anomaly detection

enum detection_result {
    NORMAL,
    SUSPICIOUS,
    DDoS
};

static bool running = true;

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_stats {
    struct flow_key key;
    uint64_t packet_count;
    uint64_t byte_count;
    uint64_t first_seen;
    uint64_t last_seen;
    enum detection_result classification;
    uint8_t threat_score;  // 0-100, used by expensive classifier
};

static struct flow_stats flow_table[MAX_FLOWS];
static uint32_t flow_count = 0;

static struct flow_stats* flow_lookup_or_create(struct flow_key *key, uint64_t timestamp)
{
    for (uint32_t i = 0; i < flow_count; i++) {
        if (flow_table[i].key.src_ip == key->src_ip &&
            flow_table[i].key.dst_ip == key->dst_ip &&
            flow_table[i].key.src_port == key->src_port &&
            flow_table[i].key.dst_port == key->dst_port &&
            flow_table[i].key.protocol == key->protocol) {
            return &flow_table[i];
        }
    }

    if (flow_count >= MAX_FLOWS) {
        return NULL;
    }

    flow_table[flow_count].key = *key;
    flow_table[flow_count].packet_count = 0;
    flow_table[flow_count].byte_count = 0;
    flow_table[flow_count].first_seen = timestamp;
    flow_table[flow_count].last_seen = timestamp;
    flow_table[flow_count].classification = NORMAL;
    flow_table[flow_count].threat_score = 0;

    return &flow_table[flow_count++];
}

/* Stage 1: Fast threshold/statistical filter */
static enum detection_result fast_filter(struct flow_stats *flow)
{
    uint64_t duration = flow->last_seen - flow->first_seen;
    if (duration == 0) {
        return NORMAL;
    }

    uint64_t pps = (flow->packet_count * rte_get_tsc_hz()) / duration;
    uint64_t bps = (flow->byte_count * rte_get_tsc_hz()) / duration;

    if (pps > PACKET_RATE_THRESHOLD || bps > BYTE_RATE_THRESHOLD) {
        return SUSPICIOUS;
    }

    return NORMAL;
}

/* Stage 2: Mark suspicious traffic for further analysis */
static void mark_suspicious(struct flow_stats *flow)
{
    if (flow->classification == SUSPICIOUS) {
        flow->threat_score = 50;
    }
}

/* Stage 3: Expensive classifier (template for future implementation) */
static enum detection_result expensive_classifier(struct flow_stats *flow)
{
    if (flow->classification != SUSPICIOUS) {
        return NORMAL;
    }

    /* TODO: Implement expensive detection logic here
     *
     * Placeholder for advanced classification:
     * - Payload analysis / entropy calculation
     * - Statistical anomaly detection
     * - Machine learning inference
     * - Packet pattern matching
     * - Protocol anomalies
     *
     * Should set flow->threat_score (0-100) and return NORMAL or DDoS
     */

    flow->threat_score = 75;  // Placeholder
    return NORMAL;  // Replace with actual classification
}

static void handle_signal(int signal)
{
    //Stop things if needed
    if (signal == SIGINT || signal == SIGTERM) {
        running = false;
    }
}



//Initialize the port with the given port number and memory pool
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    struct rte_eth_dev_info dev_info;

    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        printf("Could not get device info for port %u\n", port);
        return ret;
    }

    ret = rte_eth_dev_configure(port, 1, 0, &port_conf);
    if (ret < 0) {
        printf("Could not configure port %u\n", port);
        return ret;
    }
    ret = rte_eth_rx_queue_setup(
        port,
        0,                      // queue ID
        RX_RING_SIZE,
        rte_eth_dev_socket_id(port),
        NULL,
        mbuf_pool
    );

    if (ret < 0) {
        printf("Could not setup RX queue\n");
        return ret;
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        printf("Could not start port %u\n", port);
        return ret;
    }

    printf("Port %u started successfully.\n", port);

    return 0;
}



int main(void) {
    
    // Say Hi :)...

    rte_eal_init(0, NULL);
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8192, 250, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    port_init(0, mbuf_pool);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Starting packet processing loop...\n");

    while(running){
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);
        if (nb_rx == 0) {
            continue;
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *pkt = bufs[i];
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

            if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
            struct flow_key key = {
                .src_ip = ip->src_addr,
                .dst_ip = ip->dst_addr,
                .protocol = ip->next_proto_id
            };

            if (key.protocol == IPPROTO_TCP) {
                struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
                key.src_port = tcp->src_port;
                key.dst_port = tcp->dst_port;
            } else if (key.protocol == IPPROTO_UDP) {
                struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
                key.src_port = udp->src_port;
                key.dst_port = udp->dst_port;
            } else {
                key.src_port = 0;
                key.dst_port = 0;
            }

            uint64_t now = rte_rdtsc();
            struct flow_stats *flow = flow_lookup_or_create(&key, now);
            if (flow) {
                flow->packet_count++;
                flow->byte_count += pkt->pkt_len;
                flow->last_seen = now;

                /* Stage 1: Fast threshold filter */
                flow->classification = fast_filter(flow);

                /* Stage 2: Mark suspicious traffic */
                if (flow->classification == SUSPICIOUS) {
                    mark_suspicious(flow);

                    /* Stage 3: Expensive classifier (optional, only if marked suspicious) */
                    flow->classification = expensive_classifier(flow);
                }
            }
        }

        rte_pktmbuf_free_bulk(bufs, nb_rx);
    }

    printf("Shutting down. Processed %u flows.\n", flow_count);
    // printf("Hello, World!\n");




    return 0;
}
