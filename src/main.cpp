#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <iostream>
#include <string>
#include <cstring>
#include <cinttypes>
#include <unordered_map>
#include <memory>
#include <vector>
#include <ctime>
#include <iomanip>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>


#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "dns.h"
#include "config.h"
#include "worker.h"
#include "logger.h"


/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
//#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ
#define MEMPOOL_CACHE_SZ        250

/* Number of RX ring descriptors */
#define NB_RXD                  128

/* Number of TX ring descriptors */
#define NB_TXD                  512

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_MAX_KTHREAD 32

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

#define MAX_RX_QUEUE_PER_LCORE 16

#define BURST_TX_WAIT_US 1
uint32_t burst_tx_delay_time = BURST_TX_WAIT_US;

static uint64_t total_send_out;


/*
 * Structure of port parameters
 */
struct kni_port_params {
	uint16_t port_id;/* Port ID */

	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	unsigned lcore_work; /* lcore ID for WORK */
	unsigned lcore_send; /* lcore ID for SEND */

	struct rte_kni* kni; /* KNI context pointers */

	struct rte_ring* rx_ring;
	struct rte_ring* tx_ring;
	struct rte_ring* kni_ring;
} __rte_cache_aligned;

static struct kni_port_params* kni_port_params_array[RTE_MAX_ETHPORTS];


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf;

/* Mempool for mbufs */
static struct rte_mempool* pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

volatile bool force_quit;

uint32_t  local_ip;

std::unordered_map<std::string, std::string> alldomain;
std::shared_ptr<dnslog::Logger> logger;


Worker worker;

static void
stats_display(uint8_t port_id)
{
	struct rte_eth_stats stats;
	rte_eth_stats_get(port_id, &stats);
    std::cout << "port:" << (uint16_t) port_id << "  "
              << "rx:" << stats.ipackets << " p/s  "
              << stats.ibytes << " bytes/s  "
              << "tx:" << stats.opackets << " p/s  "
              << stats.obytes << " bytes/s  "
              << "dropped:" << stats.imissed << "\n";
    rte_eth_stats_reset(port_id);
}

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT) {
		printf("The processing is going to stop\n");

        std::cout << "total_dns_pkts:" << worker.decoder.total_dns_pkts << "\n";
        std::cout << "total_enqueue :" << worker.decoder.total_enqueue << "\n";
        std::cout << "total_send_out:" << total_send_out << "\n";

        force_quit = true;
	} else if (signum == SIGUSR1) {
        stats_display(0);
    }
}

static void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

static inline
uint32_t get_netorder_ip(const char *ip)
{
	return inet_addr(ip);
}


/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void
kni_ingress(struct kni_port_params *p)
{
	unsigned nb_rx;

    struct timespec nano;
    nano.tv_sec = 0;
    nano.tv_nsec = 1000;

    struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_ring *rx_ring;

	if (unlikely(p == NULL))
		return;

    rx_ring = p->rx_ring;

    while (!force_quit) {
        /* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(0, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx == 0)) {
            nanosleep(&nano, NULL);
		    continue;
        }

        unsigned int sent = rte_ring_sp_enqueue_burst(rx_ring, (void * const *)pkts_burst, nb_rx);
        if (unlikely(sent < nb_rx)) {
            while (sent < nb_rx)
                rte_pktmbuf_free(pkts_burst[sent++]);
        }
	}
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void
kni_egress(struct kni_port_params *p)
{
	unsigned nb_rx, num;

    struct timespec nano;
    nano.tv_sec = 0;
    nano.tv_nsec = 1000;

    struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_ring *kni_ring;

	if (unlikely(p == NULL))
		return;

	kni_ring = p->kni_ring;

    while (!force_quit) {
		nb_rx = rte_ring_sc_dequeue_burst(kni_ring, (void **)pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx == 0)) {
            nanosleep(&nano, NULL);
			continue;
		}

		num = rte_kni_tx_burst(p->kni, pkts_burst, nb_rx);
		rte_kni_handle_request(p->kni);
		if (unlikely(num < nb_rx)) {
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
		}
	}
}

static void
ring_to_kni(void *arg)
{
	uint8_t j;

    struct timespec nano;
    nano.tv_sec = 0;
    nano.tv_nsec = 1000;

	unsigned ret, sent;
	uint32_t nb_rx;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
	struct rte_ring *kni_ring;

	struct kni_port_params *p = (struct kni_port_params *) arg;

	rx_ring = p->rx_ring;
	tx_ring = p->tx_ring;
	kni_ring = p->kni_ring;

    while (!force_quit) {
		nb_rx = rte_ring_sc_dequeue_burst(rx_ring, (void **)pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx == 0)) {
            nanosleep(&nano, NULL);
			continue;
		}

		/* Prefetch first packets */
		for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
		}

		/* Prefetch and forward already prefetched packets */
		for (j = 0; j < (int)(nb_rx - PREFETCH_OFFSET); j++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));

			ret = worker.decoder.process_pkts(pkts_burst[j]);
			if (ret) {
				worker.decoder.total_enqueue++;
				sent = rte_ring_sp_enqueue_burst(tx_ring, (void* const*)&pkts_burst[j], ret);
            } else {
                sent = rte_ring_sp_enqueue_burst(kni_ring, (void* const*)&pkts_burst[j], 1);
			}

			if (unlikely(sent < ret)) {
                std::cout << "enqueue error" << "\n";
                rte_pktmbuf_free(pkts_burst[sent]);
			}
		}

		/* Forward remaining prefetched packets */
		for (; j < nb_rx; j++) {
			ret = worker.decoder.process_pkts(pkts_burst[j]);
			if (ret) {
				worker.decoder.total_enqueue++;
				sent = rte_ring_sp_enqueue_burst(tx_ring, (void* const*)&pkts_burst[j], ret);
            } else {
				sent = rte_ring_sp_enqueue_burst(kni_ring, (void* const*)&pkts_burst[j], 1);
			}

			if (unlikely(sent < ret)) {
                std::cout << "enqueue error" << "\n";
                rte_pktmbuf_free(pkts_burst[sent]);
			}
		}
	}
}

static void
send_to_eth(void *arg)
{
	uint8_t port_id;

    struct timespec nano;
    nano.tv_sec = 0;
    nano.tv_nsec = 1000;

	uint16_t nb_tx, num;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_ring *tx_ring;

	struct kni_port_params *p = (struct kni_port_params *) arg;
	port_id = p->port_id;

    while (!force_quit) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni, pkts_burst, PKT_BURST_SZ);
        if (likely(num)) {
            /* Burst tx to eth */
            nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, num);
            if (unlikely(nb_tx < num)) {
                /* Free mbufs not tx to NIC */
                kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
            }
        }


        tx_ring = p->tx_ring;
        num = rte_ring_sc_dequeue_burst(tx_ring, (void **)pkts_burst, PKT_BURST_SZ);
        if (unlikely(num == 0)) {
            nanosleep(&nano, NULL);
            continue;
        }

        /* Burst tx to eth */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, num);
        total_send_out += num;
        if (unlikely(nb_tx < num)) {
            /* Free mbufs not tx to NIC */
            std::cout << "dequeue error\n";
            kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
        }
    }
}

static int
main_loop(__rte_unused void *arg)
{
	uint8_t i, nb_ports = rte_eth_dev_count();
	const unsigned lcore_id = rte_lcore_id();
	enum lcore_rxtx {
		LCORE_NONE,
		LCORE_RX,
		LCORE_TX,
		LCORE_WORK,
		LCORE_SEND,
		LCORE_MAX
	};
	enum lcore_rxtx flag = LCORE_NONE;

	for (i = 0; i < nb_ports; i++) {
		if (!kni_port_params_array[i])
			continue;
		if (kni_port_params_array[i]->lcore_rx == (uint8_t)lcore_id) {
			flag = LCORE_RX;
			break;
		} else if (kni_port_params_array[i]->lcore_tx == (uint8_t)lcore_id) {
			flag = LCORE_TX;
			break;
		} else if (kni_port_params_array[i]->lcore_work == (uint8_t)lcore_id) {
			flag = LCORE_WORK;
			break;
		} else if (kni_port_params_array[i]->lcore_send == (uint8_t)lcore_id) {
			flag = LCORE_SEND;
			break;
		}
	}

	if (flag == LCORE_RX) {
		RTE_LOG(INFO, APP, "Lcore %u is reading from port %d\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);
		kni_ingress(kni_port_params_array[i]);
	} else if (flag == LCORE_TX) {
		RTE_LOG(INFO, APP, "Lcore %u is writing to port %d\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);
		kni_egress(kni_port_params_array[i]);
	} else if (flag == LCORE_WORK) {
		RTE_LOG(INFO, APP, "Lcore %u is working to port %d\n",
					kni_port_params_array[i]->lcore_work,
					kni_port_params_array[i]->port_id);
		ring_to_kni(kni_port_params_array[i]);
    } else if (flag == LCORE_SEND) {
		RTE_LOG(INFO, APP, "Lcore %u is sending to port %d\n",
					kni_port_params_array[i]->lcore_send,
					kni_port_params_array[i]->port_id);
		send_to_eth(kni_port_params_array[i]);
	} else
		RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);

	return 0;
}

/* Display usage instructions */
static void
print_usage(const char *prgname)
{
	RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P "
		   "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
		   "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
		   "    -p PORTMASK: hex bitmask of ports to use\n"
		   "    -P : enable promiscuous mode\n"
		   "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
		   "port and lcore configurations\n",
	           prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t
parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t)num;
}

static void
print_config(void)
{
	uint32_t i;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, APP, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
					p[i]->lcore_rx, p[i]->lcore_tx);
		/*for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, APP, "Kernel thread lcore ID: %u\n",
							p[i]->lcore_k[j]);*/
	}
}

static int
parse_config(const char *arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_RX,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];
	uint8_t port_id, nb_kni_port_params = 0;

	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	while (((p = strchr(p0, '(')) != NULL) &&
		nb_kni_port_params < RTE_MAX_ETHPORTS) {
		p++;
		if ((p0 = strchr(p, ')')) == NULL)
			goto fail;
		size = p0 - p;
		if (size >= sizeof(s)) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				printf("Invalid config parameters\n");
				goto fail;
			}
		}

		i = 0;
		port_id = (uint8_t)int_fld[i++];
		if (port_id >= RTE_MAX_ETHPORTS) {
			printf("Port ID %d could not exceed the maximum %d\n",
						port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			printf("Port %d has been configured\n", port_id);
			goto fail;
		}

		kni_port_params_array[port_id] = (struct kni_port_params *)
			rte_zmalloc("KNI_port_params",
				    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
        if (kni_port_params_array[port_id] == NULL)
            return -ENOMEM;

		kni_port_params_array[port_id]->port_id = port_id;
		kni_port_params_array[port_id]->lcore_rx = (uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_tx = (uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_work = (uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_send = (uint8_t)int_fld[i++];

		if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
			kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE ||
			kni_port_params_array[port_id]->lcore_work >= RTE_MAX_LCORE ||
			kni_port_params_array[port_id]->lcore_send >= RTE_MAX_LCORE) {
			printf("lcore_rx %u or lcore_tx %u ID could not "
						"exceed the maximum %u\n",
				kni_port_params_array[port_id]->lcore_rx,
				kni_port_params_array[port_id]->lcore_tx,
						(unsigned)RTE_MAX_LCORE);
			goto fail;
		}

		/*for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] = (uint8_t)int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;*/
	}
	print_config();

	return 0;

fail:
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

	return -1;
}

static int
validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
				"to port ids specified in --config\n");

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_rx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d receiving not enabled\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d transmitting not enabled\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_work)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d working not enabled\n",
					kni_port_params_array[i]->lcore_work,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_send)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d sending not enabled\n",
					kni_port_params_array[i]->lcore_send,
					kni_port_params_array[i]->port_id);
	}

	return 0;
}

#define CMDLINE_OPT_CONFIG  "config"

/* Parse the arguments given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, longindex, ret = 0;
	const char *prgname = argv[0];
	static struct option longopts[] = {
		{CMDLINE_OPT_CONFIG, required_argument, NULL, 0},
		{NULL, 0, NULL, 0}
	};

	/* Disable printing messages within getopt() */
	opterr = 0;

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "p:", longopts,
						&longindex)) != EOF) {
		switch (opt) {
		case 'p':
			ports_mask = parse_unsigned(optarg);
			break;

		case 0:
			if (!strncmp(longopts[longindex].name,
				     CMDLINE_OPT_CONFIG,
				     sizeof(CMDLINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("Invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}
			break;

		default:
			print_usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid option specified\n");
		}
	}

	/* Check that options were parsed ok */
	if (validate_parameters(ports_mask) < 0) {
		print_usage(prgname);
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	}

	return ret;
}

static void
init_ring()
{
	int i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			struct rte_ring *rx_ring, *tx_ring, *kni_ring;
			char name[32] = {0};

            snprintf(name, sizeof(name), "ring_rx_%u", i);
            rx_ring = rte_ring_create(name, 1024 * 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (rx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create RX ring, %s, %s():%d\n", 
                        rte_strerror(rte_errno), __func__, __LINE__);
            kni_port_params_array[i]->rx_ring = rx_ring;
                

            snprintf(name, sizeof(name), "ring_tx_%u", i);
            tx_ring = rte_ring_create(name, 1024 * 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (tx_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create TX ring, %s, %s():%d\n", 
                        rte_strerror(rte_errno), __func__, __LINE__);
            kni_port_params_array[i]->tx_ring = tx_ring;

            snprintf(name, sizeof(name), "ring_kni_%u", i);
            kni_ring = rte_ring_create(name, 1024 * 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (kni_ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create KNI ring, %s, %s():%d\n", 
                        rte_strerror(rte_errno), __func__, __LINE__);

            kni_port_params_array[i]->kni_ring = kni_ring;
		}
	}
}

/* Initialize KNI subsystem */
static void
init_kni(void)
{
	unsigned int num_of_kni_ports = 0, i;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			//num_of_kni_ports += (params[i]->nb_lcore_k ?
				//params[i]->nb_lcore_k : 1);
            num_of_kni_ports++;
		}
	}

	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

/* Initialise a single port on an Ethernet device */
static void
init_port(uint8_t port)
{
	int ret;
	uint16_t q;
	uint8_t nb_rx_queue = 1;
	//uint16_t nb_tx_queue = rte_lcore_count();
	uint16_t nb_tx_queue = 1;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);

	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

	ret = rte_eth_dev_configure(port, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

	for (q = 0; q < nb_rx_queue; q++) {
		ret = rte_eth_rx_queue_setup(port, q, NB_RXD,
			rte_eth_dev_socket_id(port), NULL, pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
					"port%u (%d)\n", (unsigned)port, ret);
	}

	for (q = 0; q < nb_tx_queue; q++) {
		ret = rte_eth_tx_queue_setup(port, q, NB_TXD,
			rte_eth_dev_socket_id(port), NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
					"port%u (%d)\n", (unsigned)port, ret);
	}

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
						(unsigned)port, ret);

	rte_eth_promiscuous_enable(port);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	int ret;
	struct rte_eth_conf conf;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

	return ret;
}

static int
kni_alloc(uint8_t port_id)
{
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
	conf.group_id = (uint16_t)port_id;
	conf.mbuf_size = MAX_PACKET_SZ;
	/*
	 * The first KNI device associated to a port
	 * is the master, for multiple kernel thread
	 * environment.
	 */

		struct rte_kni_ops ops;
		struct rte_eth_dev_info dev_info;

		memset(&dev_info, 0, sizeof(dev_info));
		rte_eth_dev_info_get(port_id, &dev_info);
		conf.addr = dev_info.pci_dev->addr;
		conf.id = dev_info.pci_dev->id;

		memset(&ops, 0, sizeof(ops));
		ops.port_id = port_id;
		ops.change_mtu = kni_change_mtu;
		ops.config_network_if = kni_config_network_interface;

		kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);

	if (!kni)
		rte_exit(EXIT_FAILURE, "Fail to create kni for "
					"port: %d\n", port_id);
	params[port_id]->kni = kni;

	return 0;
}

static int
kni_free_kni(uint8_t port_id)
{
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	if (rte_kni_release(p[port_id]->kni))
		printf("Fail to release kni\n");
	p[port_id]->kni = NULL;

	rte_eth_dev_stop(port_id);

	return 0;
}

static void
cleanup_ring(void)
{
 	int i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
            struct rte_ring *rx_ring, *tx_ring, *kni_ring;

            rx_ring = kni_port_params_array[i]->rx_ring;
            if (rx_ring)
                rte_ring_free(rx_ring);
                        
            tx_ring = kni_port_params_array[i]->tx_ring;
            if (tx_ring)
                rte_ring_free(tx_ring);

            kni_ring = kni_port_params_array[i]->kni_ring;
            if (kni_ring)
                rte_ring_free(kni_ring);
		}
	}
}

/* Create the mbuf pool */
static void
pool_create()
{
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SZ, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
}

static void
pool_free()
{
    if (pktmbuf_pool)
        rte_mempool_free(pktmbuf_pool);
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main(int argc, char** argv)
{
	int ret;
	uint8_t nb_sys_ports, port;
	unsigned i;

	/* Associate signal_hanlder function with USR signals */
    force_quit = false;
    signal(SIGUSR1, signal_handler);
	signal(SIGINT, signal_handler);

    logger = dnslog::Logger::getLogger();

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);

	argc -= ret;
	argv += ret;

	config cfg("../conf/cfg.ini");
	if (!cfg.parse())
		return -1;

    logger->set_level(cfg.log.level);


    local_ip = get_netorder_ip(cfg.server.ip.c_str());


	/* Parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

	pool_create();

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Check if the configured port ID is valid */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i] && i >= nb_sys_ports)
			rte_exit(EXIT_FAILURE, "Configured invalid port ID %u\n", i);

	/* Initialize KNI subsystem */
	init_kni();

	init_ring();

	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if (!(ports_mask & (1 << port)))
			continue;
		init_port(port);

		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
				"%d ports for kni\n", RTE_MAX_ETHPORTS);

		kni_alloc(port);
	}

	check_all_ports_link_status(nb_sys_ports, ports_mask);

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);

	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}

	/* Release resources */
	for (port = 0; port < nb_sys_ports; port++) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
#ifdef RTE_LIBRTE_XEN_DOM0
	rte_kni_close();
#endif
    cleanup_ring();

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

    pool_free();

	return 0;
}
