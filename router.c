#include "queue.h"
#include "skel.h"

int arp_table_size = 0;
struct arp_entry* arp_table;

int route_table_size = 0;
struct route_table_entry *route_table;

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	arp_table = malloc(100000 * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Can't alloc arp table");

	route_table = malloc(100000 * sizeof(struct route_table_entry));
	DIE(route_table == NULL, "Can't alloc route table");
	route_table_size = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_size, sizeof(struct route_table_entry), comparator);

	queue q = queue_create();

	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");			

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));
			if (arp_hdr->op == htons(ARPOP_REQUEST)) {
				send_reply(&arp_hdr, &eth_hdr, &m);
				printf("\n");
				continue;
			} else if (arp_hdr->op == htons(ARPOP_REPLY)) {
				// Create a new entry
				struct arp_entry* new_entry = create_new_entry(arp_hdr->spa, arp_hdr->sha);
				// Add it to the arp table
				insert_entry(new_entry, &arp_table, &arp_table_size);
				// Remove from queue the packets of who's destination mac address we recieved
				queue aux_queue = queue_create();
				while(!queue_empty(q)) {
					packet* first = (packet*) queue_deq(q);
					struct ether_header *first_eth_hdr = (struct ether_header*)first->payload;
					struct iphdr *first_ip_hdr = (struct iphdr*)(first->payload + sizeof(struct ether_header));

					struct route_table_entry *next = best_route(route_table, route_table_size, first_ip_hdr->daddr);

					if (next == NULL) {
						send_icmp(&m, 3);
						continue;
					}

					if(new_entry->ip == next->next_hop) {
						first->interface = next->interface;
						memcpy(first_eth_hdr->ether_dhost, new_entry->mac, ETH_ALEN);
						send_packet(first);
					} else {
						queue_enq(aux_queue, first);
					}
				}
				// Put the unsent packets in the old queue, sorted in the same order
				while (!queue_empty(q)) {
					queue_enq(aux_queue, queue_deq(q));
				}
				while (!queue_empty(aux_queue)) {
					queue_enq(q, queue_deq(aux_queue));
				}
				continue;
			}
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));

			if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				struct icmphdr *icmp_hdr = read_icmp(&m);
				if (icmp_hdr != NULL) {
					if (icmp_hdr->type == 8) {
						send_icmp(&m, 0);
					}
				}
				continue;
			}

			if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0 ) {
				continue;
			}

			if (ip_hdr->ttl <= 1) {
				send_icmp(&m, 11);
				continue;
			}

			struct route_table_entry *next = best_route(route_table, route_table_size,ip_hdr->daddr);

			if (next == NULL) {
				send_icmp(&m, 3);
				continue;
			}

			struct arp_entry *next_entry = NULL;
			for(int i = 0; i < arp_table_size; i++) {
				if(arp_table[i].ip == next->next_hop) 
					next_entry = &arp_table[i];
			}

			if (next_entry == NULL) {
				// Copy the old packet in the queue
				packet *copy = malloc(sizeof(m));
				memcpy(copy, &m, sizeof(m));
				queue_enq(q, copy);

				// Create a new packet
				packet request_packet;
				request_packet.interface = next->interface;
				request_packet.len = 42;
				memset(request_packet.payload, 0, 1600);

				// Create an ETH header for the arp request
				struct ether_header* request_ether = malloc(sizeof(struct ether_header));
				request_ether->ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(request_packet.interface, request_ether->ether_shost);
				memset(request_ether->ether_dhost, 0xff, ETH_ALEN);

				// Create an arp header
				struct arp_header* arp_request_header = malloc(sizeof(struct arp_header));
				arp_request_header->htype = htons(ARPHRD_ETHER);
				arp_request_header->ptype = htons(2048);
				arp_request_header->op = ntohs(1);
				arp_request_header->hlen = ETH_ALEN;
				arp_request_header->plen = 4;
				get_interface_mac(request_packet.interface, arp_request_header->sha);
				struct in_addr ipaddress;
				inet_aton(get_interface_ip(request_packet.interface), &ipaddress);
				arp_request_header->spa = ipaddress.s_addr;
				memset(arp_request_header->tha, 0x00, ETH_ALEN);
				arp_request_header->tpa = next->next_hop;

				// Move the arp header in the packet and replace the ip header
				memcpy(request_packet.payload, request_ether, sizeof(struct ether_header));
				memcpy(request_packet.payload + sizeof(struct ether_header), arp_request_header, sizeof(struct arp_header));
				send_packet(&request_packet);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			m.interface = next->interface;
			memcpy(eth_hdr->ether_dhost, next_entry->mac, ETH_ALEN);
			get_interface_mac(next->interface, eth_hdr->ether_shost);
			send_packet(&m);
		}
	}
}
