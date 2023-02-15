#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name) {
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(packet *m)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	int ret;
	ret = write(interfaces[m->interface], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m)
{
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set,
				NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i) {
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}


uint16_t icmp_checksum(uint16_t *data, size_t size)
{
	unsigned long cksum = 0;
	while(size >1) {
		cksum += *data++;
		size -= sizeof(unsigned short);
	}
	if (size)
		cksum += *(unsigned short*)data;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (uint16_t)(~cksum);
}


uint16_t ip_checksum(uint8_t *data, size_t size)
{
	// Initialise the accumulator.
	uint64_t acc = 0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset = ((uintptr_t)data) &3;
	if (offset) {
		size_t count = 4 - offset;
		if (count > size)
			count = size;
		uint32_t word = 0;
		memcpy(offset + (char *)&word, data, count);
		acc += ntohl(word);
		data += count;
		size -= count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end = data + (size & ~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}

	size &= 3;

	// Handle any partial block at the end of the data.
	if (size) {
		uint32_t word = 0;
		memcpy(&word, data, size);
		acc += ntohl(word);
	}

	// Handle deferred carries.
	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask)  + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
	}
	return j;
}

int parse_arp_table(char *path, struct arp_entry *arp_table)
{
	FILE *f;
	fprintf(stderr, "Parsing ARP table\n");
	f = fopen(path, "r");
	DIE(f == NULL, "Failed to open arp_table.txt");
	char line[100];
	int i = 0;
	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];
		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}
	fclose(f);
	fprintf(stderr, "Done parsing ARP table.\n");
	return i;
}

struct arp_entry* create_new_entry(uint32_t ip, uint8_t* mac) {
	struct arp_entry* new_entry = malloc(sizeof(struct arp_entry));
	DIE(new_entry == NULL, "Couldn't create a new arp entry");
	new_entry->ip = ip;
	memcpy(new_entry->mac, mac, ETH_ALEN);
	return new_entry;
}

void insert_entry(struct arp_entry *entry, struct arp_entry** arp_table, int *size) {
	for (int i = 0; i < (*size); i ++) {
		if (entry->mac == (*arp_table)[i].mac)
			return;
	}
	(*arp_table)[(*size)] = *entry;
	(*size)++;
}

void send_reply(struct arp_header** arp_hdr, struct ether_header** eth_hdr, packet* m) {
	// Swap the addresses in the ethernet header
	// and set the source address as current interface's address
	memcpy((*eth_hdr)->ether_dhost, (*eth_hdr)->ether_shost, ETH_ALEN);
	get_interface_mac(m->interface, (*eth_hdr)->ether_shost);

	// Modify the arp to make it a reply and swap the addresses
	uint8_t req_sender_mac[ETH_ALEN];
	memcpy(req_sender_mac, (*arp_hdr)->sha, ETH_ALEN);
	uint32_t req_sender_ip = (*arp_hdr)->spa;

	(*arp_hdr)->op = ntohs(2); // Change the type of operation
	get_interface_mac(m->interface, (*arp_hdr)->sha);
	(*arp_hdr)->spa = (*arp_hdr)->tpa;
	memcpy((*arp_hdr)->tha, req_sender_mac, ETH_ALEN);
	(*arp_hdr)->tpa = req_sender_ip;
	
	// Send the reply back to the requester
	send_packet(m);
}

struct icmphdr* read_icmp(packet *m) {
	struct ether_header* eth_hdr = (struct ether_header*) m->payload;
	struct iphdr* ip_hdr = (struct iphdr*) (m->payload + sizeof(struct ether_header));
	if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
		return NULL;
	}
	if (ip_hdr->protocol != 1) {
		return NULL;
	}
	struct icmphdr* icmp_hdr = (struct icmphdr*) (m->payload +
						(sizeof(struct ether_header) + sizeof(struct iphdr)));
	return icmp_hdr;
}

void send_icmp(packet *m, int type) {
	uint8_t aux_mac[ETH_ALEN];
	uint32_t aux_ip;
	// Swap the mac addresses in the ethernet header
	struct ether_header *eth_hdr = (struct ether_header*) m->payload;
	memcpy(aux_mac, eth_hdr->ether_dhost, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, aux_mac, ETH_ALEN);

	// Swap the ip and mac addresses in the ethernet header
	struct iphdr *ip_hdr = (struct iphdr*) (m->payload + sizeof(struct ether_header));
	aux_ip = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->daddr = aux_ip;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->ihl = 5;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

	struct icmphdr *icmp_hdr = (struct icmphdr*) (m->payload + (sizeof(struct ether_header) + sizeof(struct iphdr)));

	m->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum(icmp_hdr, sizeof(struct icmphdr));

	send_packet(m);
}

int comparator(const void *r1, const void *r2)  { 	
	uint32_t mask1 = ntohl(((struct route_table_entry *) r1)->mask);
	uint32_t mask2 = ntohl(((struct route_table_entry *) r2)->mask);
	uint32_t prefix1 = ntohl(((struct route_table_entry *) r1)->prefix);
	uint32_t prefix2 = ntohl(((struct route_table_entry *) r2)->prefix);
	
	if ((prefix1 & mask1 & mask2) != (prefix2 & mask1 & mask2)) {
		return (int)((prefix1 & mask1 & mask2) - (prefix2 & mask1 & mask2));
	} else {
		return mask2 - mask1;
	}
}

/**
 * Inspired by: https://en.wikipedia.org/wiki/Binary_search_algorithm ->
 * -> Procedure for finding the leftmost element
 */
struct route_table_entry *best_route(struct route_table_entry* arr, int route_table_size,uint32_t ip) {
	int l = 0;
	int r = route_table_size;
    while (r > l) {
        int mid = (r + l) / 2;

		if (ntohl(arr[mid].prefix) < (ntohl(ip) & ntohl(arr[mid].mask))) {
			l = mid + 1;
		} else {
			r = mid;
		}
    }

	if ((arr[l].mask & ip) != arr[l].prefix) {
		return NULL;
	}
	return &arr[l];
}
