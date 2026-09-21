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

    /*
     * 1 RX queue
     * 0 TX queues
     */
    ret = rte_eth_dev_configure(port, 1, 0, &port_conf);
    if (ret < 0) {
        printf("Could not configure port %u\n", port);
        return ret;
    }

    /*
     * Create RX queue 0.
     */
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

    /*
     * Start NIC.
     */
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

    
    printf("Hello, World!\n");




    return 0;
}
