/*-
 *   BSD LICENSE
 *
 *   Copyright 2017 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_hexdump.h>

#define IP_STR_LEN (16)

#define NB_MBUF  (8192)
#define MEMPOOL_CACHE_SIZE (512)

#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_DEFTTL  (64)
#define IP_CLIENT_ADDR ((192U << 24) | (168 << 16) | (0 << 8) | 1)
#define IP_SERVER_ADDR ((192U << 24) | (168 << 16) | (0 << 8) | 2)
#define DPDK_UDP_PORT 10101

#define RTE_TEST_RX_DESC_DEFAULT 256
#define RTE_TEST_TX_DESC_DEFAULT 256
static uint16_t rxd_n = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t txd_n = RTE_TEST_TX_DESC_DEFAULT;

static volatile int force_quit;

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.offloads = 0, /* Header Split disabled/IP checksum offload disabled/
				  VLAN filtering disabled/Jumbo Frame Support disabled/
				  CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct ipoib_ping_args {
	/* UDP port on which application listen for address exchange. */
	uint16_t udp_port;
	/* IP address on which application listen for address exchange. */
	char ip[IP_STR_LEN];
	/* Flag to choose client/server mode. */
	uint8_t is_server;
	/* When set, Tx checksum offload will be used. */
	uint8_t checksum;
	/* When set, application run in debug mode. */
	uint8_t debug;
};

struct ipoib_ping_args args = {
	.udp_port = 8888,
};

struct address_info {
	uint16_t mtu;
	struct rte_eth_ib_av av;
	unsigned int av_sz;
};

static struct address_info peer_addr;
static struct rte_mempool *pktmbuf_pool;

/**
 * Returns the IB local address vector.
 *
 * @param[in] port
 *   Port index.
 * @param[out] info
 *   Infiniband address vector information.
 *
 * @return
 *   0 upon success, negtaive errno otherwise.
 */
static int
create_local_info(uint8_t port, struct address_info *info)
{
	int err = 0;

	err = rte_eth_dev_get_mtu(port, &info->mtu);
	if (err)
		return err;
	err = rte_eth_dev_get_local_ib_av(port, &info->av);
	return err;
}

/**
 * Exchanges Infiniband addressing information between
 * Server and a client.
 *
 * @param[in] ports_n
 *   Number of ports.
 *
 * @return
 *   0 upon success, -1 otherwise.
 */
static int
address_exchange(uint8_t ports_n) {
	struct sockaddr_in si;
	int s;
	int ret = 0;
	uint8_t port_id;

	/* Create UDP socket. */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	si.sin_family = AF_INET;
	si.sin_port = htons(args.udp_port);
	si.sin_addr.s_addr = htonl(INADDR_ANY);
	/* Bind socket to port. */
	ret = bind(s, (struct sockaddr *)&si, sizeof(si));
	if (ret < 0)
		return -1;
	/* Keep listen for data till all ports are recognized. */
	for (port_id = 0 ; port_id < ports_n ; port_id++) {
		uint8_t received = 0;
		while (!received) {
			if (args.is_server) {
				struct sockaddr_in si_req;
				struct address_info req = {0};
				int slen = sizeof(si_req);

				/* Wait for request from client. */
				ret = recvfrom(s, (void *)&req, sizeof(req), 0,
					       (struct sockaddr *)&si_req,
					       (socklen_t *)&slen);
				assert(ret > 0);
				received = 1;
				/* Update peer address. */
				peer_addr = req;
				rte_eth_dev_translate_ib_av(port_id,
							    &peer_addr.av,
							    &peer_addr.av_sz);
				/* Response with the local address. */
				ret = create_local_info(port_id, &req);
				if (ret)
					return -1;
				sendto(s, (void *)&req, sizeof(req), 0,
				       (struct sockaddr *)&si_req,
				       sizeof(si_req));
			} else {
				struct sockaddr_in server_addr;
				struct address_info req = {0};
				int slen = sizeof(server_addr);

				bzero((char *) &server_addr,
				      sizeof(server_addr));
				server_addr.sin_family = AF_INET;
				server_addr.sin_port = htons(args.udp_port);
				inet_aton(args.ip,
					  (struct in_addr *)
					  &server_addr.sin_addr.s_addr);
				ret = create_local_info(port_id, &req);
				if (ret)
					return -1;
				sendto(s, (void *)&req, sizeof(req), 0,
				       (struct sockaddr *)&server_addr,
				       sizeof(server_addr));
				ret = recvfrom(s, (void *)&req, sizeof(req),
					       MSG_DONTWAIT,
					       (struct sockaddr *)&server_addr,
					       (socklen_t *)&slen);
				if (ret > 0) {
					received = 1;
					peer_addr = req;
					rte_eth_dev_translate_ib_av(
							port_id,
							&peer_addr.av,
							&peer_addr.av_sz);
				} else {
					usleep(1000);
				}
			}
		}
		ports_n--;
	}
	return 0;
}

static void
ipoib_ping_usage(const char *prgname)
{
	printf("%s usage:\n", prgname);
	printf("./ipoib_ping <eal args> -- --client -p <ip> <options>\n");
	printf("./ipoib_ping <eal args> -- --server <options>\n\n");
	printf("Options:\n");
	printf("-p: server ip address (client only).\n");
	printf("--client: run application as a client.\n");
	printf("--server: run application as a server.\n");
	printf("--checksum: use Tx checksum offlad (client only).\n");
	printf("--debug: enable debug logs verbosity.\n");
}

static const char short_options[] =
	"p:h"
	;

static const struct option lgopts[] = {
	{ "server", no_argument, (int *)&args.is_server, 1},
	{ "client", no_argument, (int *)&args.is_server, 0},
	{ "checksum", no_argument, (int *)&args.checksum, 1},
	{ "debug", no_argument, (int *)&args.debug, 1},
	{NULL, 0, 0, 0},
};

/**
 * Parse application arguments.
 *
 * @param[in] argc
 *   Number of args.
 * @param[in[ argv
 *   Pointer to args.
 *
 * @return
 *   0 upon success, -1 otherwise.
 */
static int
ipoib_ping_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* Server default ip. */
		case 'p':
			strncpy(args.ip, optarg, sizeof(args.ip));
			break;
		case 'h':
			ipoib_ping_usage(prgname);
			return -1;
			break;
		/* long options */
		case 0:
			break;
		default:
			ipoib_ping_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/**
 * Sets IP rule to direct traffic to application.
 *
 * @param[in] port_id
 *   Port index.
 *
 * @return
 *   Valid rte_flow pointer upon success, NULL otherwise.
 */
static struct rte_flow *
set_default_flow_rule(uint8_t port_id)
{
	int ret = 0;
	struct rte_flow *default_rule = NULL;
	struct rte_flow_error error;
	struct rte_flow_attr attr = {
		.ingress = 1,
	};
	struct rte_flow_item_udp udp_spec = {
		.hdr = {
			.dst_port = rte_cpu_to_be_16(DPDK_UDP_PORT),
		},
	};

	struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.dst_port = 0xffff,
		},
	};
	struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr = {
			.dst_addr = rte_cpu_to_be_32(args.is_server ?
						     IP_SERVER_ADDR :
						     IP_CLIENT_ADDR),
		},
	};
	struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr = {
			.dst_addr = 0xffffffff,
		},
	};
	struct rte_flow_item flow[3] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = &ipv4_spec,
			.mask = &ipv4_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.spec = &udp_spec,
			.mask = &udp_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_queue q_action = {
		.index = 0, /* Just to make it explicit. */
	};
	struct rte_flow_action actions[2] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &q_action,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};

	ret = rte_flow_validate(port_id, &attr, flow, actions, &error);
	if (ret)
		printf("Error in flow creation.\n");
	else
		default_rule = rte_flow_create(port_id, &attr, flow,
					       actions, &error);
	return default_rule;
}

/**
 * Creates Tx UDP packet.
 *
 * @return
 *   Valid rte_mbuf pointer upon success, NULL otherwise.
 */
static struct rte_mbuf *
create_tx_pkt(void)
{
	struct rte_mbuf *pkt;
	uint16_t ip_len = sizeof(struct ipv4_hdr) +
			  sizeof(struct udp_hdr);
	struct ipoib_hdr ipoib_hdr = {
		.type = rte_cpu_to_be_16(0x800),
	};
	struct ipv4_hdr ip_hdr = {
		.version_ihl = IP_VHL_DEF,
		.type_of_service = 0,
		.fragment_offset = 0,
		.time_to_live = IP_DEFTTL,
		.next_proto_id = IPPROTO_UDP,
		.packet_id = 0,
		.total_length = rte_cpu_to_be_16(ip_len),
		.src_addr = rte_cpu_to_be_32(IP_CLIENT_ADDR),
		.dst_addr = rte_cpu_to_be_32(IP_SERVER_ADDR),
	};
	struct udp_hdr udp_hdr = {
		.dst_port = rte_cpu_to_be_16(DPDK_UDP_PORT),
		.dgram_len = rte_cpu_to_be_16(sizeof(udp_hdr)),
		.dgram_cksum = 0, /* No UDP checksum. */
	};
	char *buf;

	pkt = rte_mbuf_raw_alloc(pktmbuf_pool);
	if (pkt == NULL)
		return NULL;
	rte_pktmbuf_reset_headroom(pkt);
	buf = rte_pktmbuf_mtod_offset(pkt, char *, 0);
	/* Copy IB address vector to headroom. */
	rte_memcpy((void *)((uintptr_t)buf - peer_addr.av_sz),
		   &peer_addr.av, peer_addr.av_sz);
	/* Copy packet headers. */
	rte_memcpy(buf, &ipoib_hdr, sizeof(ipoib_hdr));
	buf += sizeof(ipoib_hdr);
	rte_memcpy(buf, &ip_hdr, sizeof(ip_hdr));
	buf += sizeof(ip_hdr);
	rte_memcpy(buf, &udp_hdr, sizeof(udp_hdr));
	/* Set mbuf metadata. */
	pkt->data_len = sizeof(struct ipoib_hdr) +
			sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr);
	pkt->pkt_len = pkt->data_len;
	pkt->nb_segs = 1;
	pkt->l2_len = sizeof(struct ether_hdr);
	pkt->l3_len = sizeof(struct ipv4_hdr);
	pkt->l4_len = sizeof(struct udp_hdr);
	if (args.checksum)
		pkt->ol_flags = (PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM);
	return pkt;
}

/**
 * Worker thread main loop.
 */
static int
worker_main_loop(void *arg)
{
	unsigned int pkt_n = 0;

	(void)arg;
	while (!force_quit) {
		if (args.is_server) {
			struct rte_mbuf *pkt;
			unsigned int nb_rx;

			nb_rx = rte_eth_rx_burst(0, 0, &pkt, 1);
			pkt_n += nb_rx;
			if (nb_rx) {
				rte_pktmbuf_free(pkt);
				if (args.debug) {
					rte_hexdump(stdout, "Packet Received:",
					    (void *)rte_pktmbuf_mtod_offset(
						    pkt, char *, 0),
					    pkt->data_len);
				}
			}
		} else {
			struct rte_mbuf *pkt = create_tx_pkt();
			unsigned int nb_tx;

			if (!pkt)
				return -1;

			nb_tx = rte_eth_tx_burst(0, 0, &pkt, 1);
			pkt_n += nb_tx;
			if (!nb_tx) {
				rte_pktmbuf_free(pkt);
			} else if (args.debug) {
				rte_hexdump(stdout, "Packet Sent:",
					    (void *)rte_pktmbuf_mtod_offset(
							pkt, char *, 0),
							pkt->data_len);
			}
			usleep(1000);
		}
	}
	printf("%s is exiting, %s %u packets\n",
	       args.is_server ? "Server" : "Client",
	       args.is_server ? "Received" : "Sent",
	       pkt_n);
	return 0;
}

/**
 * Signal hanlder to stop worker thread.
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = 1;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint8_t ports_n;
	uint8_t port_id;
	unsigned int mbuf_size;
	unsigned int worker_lcore_id;
	struct rte_flow *flow = NULL;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;
	/* Set signal handler. */
	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	/* parse application arguments (after the EAL ones) */
	ret = ipoib_ping_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid IPoIB arguments\n");
	ports_n = rte_eth_dev_count_avail();
	if (ports_n == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	assert(ports_n < RTE_MAX_ETHPORTS);
	/* Exchange address vector parameters. */
	printf("Exchanging IB Addresses\n");
	ret = address_exchange(ports_n);
	/* create the mbuf pool */
	mbuf_size = peer_addr.mtu + RTE_PKTMBUF_HEADROOM;
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, mbuf_size, rte_socket_id());
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	for (port_id = 0; port_id < ports_n; port_id++) {
		/* Configure the port. */
		ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: "
				 "err=%d, port=%u\n", ret,
				 (unsigned int) port_id);
		/* Configure one Rx queue. */
		ret = rte_eth_rx_queue_setup(port_id, 0, rxd_n,
				rte_eth_dev_socket_id(port_id),	NULL,
				pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: "
				 "err=%d, port=%u\n", ret,
				 (unsigned int) port_id);
		/* Configure one Tx queue. */
		ret = rte_eth_tx_queue_setup(port_id, 0, txd_n,
				rte_eth_dev_socket_id(port_id),	NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
				 "err=%d, port=%u\n", ret,
				 (unsigned int) port_id);
		/* Add flow item to direct packet to the Rx queue. */
		flow = set_default_flow_rule(port_id);
		if (flow == NULL)
			rte_exit(EXIT_FAILURE, "Cannot set default IP rule\n");
		/* Start device. */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: "
				 "err=%d, port=%u\n", ret,
				 (unsigned int) port_id);
	}
	/* Lunch worker thread. */
	worker_lcore_id = rte_get_next_lcore(-1, 1, 0);
	if (worker_lcore_id == RTE_MAX_LCORE)
		rte_exit(EXIT_FAILURE, "no active lcore for worker thread.\n");
	printf("%s is lunching on lcore %u\n",
	       args.is_server ? "Server" : "Client", worker_lcore_id);
	rte_eal_remote_launch(worker_main_loop, NULL, worker_lcore_id);
	/* Wait worker to finish. */
	rte_eal_wait_lcore(worker_lcore_id);
	/* Cleanup. */
	for (port_id = 0; port_id < ports_n; port_id++) {
		struct rte_flow_error error;
		printf("Closing port %d...", port_id);
		rte_flow_destroy(port_id, flow, &error);
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
