#include "network_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h> 
#include <gmp.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

#ifdef _WIN32
int ipv4_pton(int af, const char *src, void *dst) {
    return InetPtonA(af, src, dst);
}

const char *ipv4_ntop(int af, const void *src, char *dst, size_t size) {
    return InetNtopA(af, src, dst, size);
}
#else
#define ipv4_pton inet_pton
#define ipv4_ntop inet_ntop
#endif


// Função auxiliar para alocar strings

char* allocate_string(int size) {
    char* str = (char*)malloc(size);
    if (!str) {
        fprintf(stderr, "Erro de alocação de memória\n");
        exit(EXIT_FAILURE);
    }
    return str;
}

// --------- Funções de Conversão IPv4, IPv6 e resumo de IPv6 ---------

char* decimal_to_binary(int decimal) {
    if (decimal == 0) {
        char* zero = allocate_string(2);
        zero[0] = '0';
        zero[1] = '\0';
        return zero;
    }

    char* binary = allocate_string(33);  
    int start = -1;

    for (int i = 31; i >= 0; i--) {
        binary[31 - i] = (decimal & (1 << i)) ? '1' : '0';
        if (binary[31 - i] == '1' && start == -1) {
            start = 31 - i;  
        }
    }

    binary[32] = '\0';

    char* trimmed_binary = allocate_string(33 - start);
    for (int i = 0; i < 33 - start; i++) {
        trimmed_binary[i] = binary[start + i];
    }

    free(binary);  
    return trimmed_binary;
}

int binary_to_decimal(const char* binary_str) {
    int decimal = 0;
    for (int i = 0; binary_str[i] != '\0'; i++) {
        decimal = (decimal << 1) | (binary_str[i] - '0');
    }
    return decimal;
}

char* hexadecimal_to_binary(const char* hex_str) {
    int decimal = hexadecimal_to_decimal(hex_str); 
    return decimal_to_binary(decimal);  
}

char* binary_to_hexadecimal(const char* binary_str) {
    int decimal = binary_to_decimal(binary_str); 
    return decimal_to_hexadecimal(decimal);  
}

char* decimal_to_hexadecimal(int decimal) {
    char* hex = allocate_string(9);  
    snprintf(hex, 9, "%X", decimal);
    return hex;
}

int hexadecimal_to_decimal(const char* hex_str) {
    int decimal;
    sscanf(hex_str, "%X", &decimal);
    return decimal;
}

char* ip_to_binary(const char* ip) {
    struct in_addr addr;
    ipv4_pton(AF_INET, ip, &addr);
    return decimal_to_binary(ntohl(addr.s_addr));
}

char* binary_to_ip(const char* binary_str) {
    int decimal = binary_to_decimal(binary_str);
    struct in_addr addr;
    addr.s_addr = htonl(decimal);
    char* ip = allocate_string(INET_ADDRSTRLEN);
    ipv4_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN);
    return ip;
}

char* ipv6_to_binary(const char* ipv6) {
    struct in6_addr addr; 

    if (ipv4_pton(AF_INET6, ipv6, &addr) != 1) {
        return NULL;
    }

    char* binary_str = allocate_string(129);  

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            binary_str[i * 8 + (7 - j)] = (addr.s6_addr[i] & (1 << j)) ? '1' : '0';
        }
    }

    binary_str[128] = '\0';
    return binary_str;
}

char* binary_to_ipv6(const char* binary_str) {
    if (strlen(binary_str) != 128) {
        return NULL;
    }

    struct in6_addr addr = {0};

    for (int i = 0; i < 16; i++) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; j++) {
            byte = (byte << 1) | (binary_str[i * 8 + j] - '0');
        }
        addr.s6_addr[i] = byte;
    }

    char* ipv6_str = allocate_string(INET6_ADDRSTRLEN);

    if (ipv4_ntop(AF_INET6, &addr, ipv6_str, INET6_ADDRSTRLEN) == NULL) {
        free(ipv6_str);
        return NULL;
    }

    return ipv6_str;
}

char* summarize_ipv6(const char* ipv6) {
    char block[8][5] = {0};
    int position = 0;
    
    char* ipv6_summarized = (char*)malloc(40 * sizeof(char));
    if (!ipv6_summarized) {
        return NULL;  
    }
    ipv6_summarized[0] = '\0';  

    for (int i = 0; i < 8; i++) {
        int block_position = 0;
        while (ipv6[position] != ':' && ipv6[position] != '\0') {
            block[i][block_position++] = ipv6[position++];
        }
        block[i][block_position] = '\0';
        position++;
    }

    for (int i = 0; i < 8; i++) {
        int j = 0;
        while (block[i][j] == '0' && j < strlen(block[i]) - 1) {
            j++;
        }
        memmove(block[i], &block[i][j], strlen(block[i]) - j + 1);
    }

    int compress = 0;
    for (int i = 0; i < 8; i++) {
        if (strcmp(block[i], "0") == 0 && !compress) {
            strcat(ipv6_summarized, ":");
            compress = 1;
            while (i < 8 && strcmp(block[i], "0") == 0) i++;
            i--;
        } else {
            strcat(ipv6_summarized, block[i]);
            if (i < 7) strcat(ipv6_summarized, ":");
            compress = 0;
        }
    }

    if (ipv6_summarized[0] == ':' && ipv6_summarized[1] == ':') {
        memmove(ipv6_summarized, ipv6_summarized + 1, strlen(ipv6_summarized));
    }
    if (ipv6_summarized[strlen(ipv6_summarized) - 1] == ':' && ipv6_summarized[strlen(ipv6_summarized) - 2] == ':') {
        ipv6_summarized[strlen(ipv6_summarized) - 1] = '\0';
    }
    
    return ipv6_summarized;
}

// --------- Funções CIDR e Máscaras ---------

char* cidr_to_mask(int cidr) {
    if (cidr < 0 || cidr > 32) {
        return NULL; 
    }

    char* mask = malloc(16);
    if (!mask) {
        return NULL; 
    }

    unsigned int mask_value = 0xFFFFFFFF << (32 - cidr);
    
    snprintf(mask, 16, "%d.%d.%d.%d",
             (mask_value >> 24) & 0xFF,
             (mask_value >> 16) & 0xFF,
             (mask_value >> 8) & 0xFF,
             mask_value & 0xFF);

    return mask;
}

int mask_to_cidr(const char* mask) {
    
    int octets[4];
    if (sscanf(mask, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) != 4) {
        return -1; 
    }

    int cidr = 0;
    for (int i = 0; i < 4; i++) {
        
        while (octets[i] > 0) {
            cidr += (octets[i] & 1);
            octets[i] >>= 1; 
        }
    }
    return cidr; 
}

char* calculate_network_address(const char* ip, int cidr) {
    struct in_addr ip_addr, mask_addr;

    ipv4_pton(AF_INET, ip, &ip_addr);

    char* mask_str = cidr_to_mask(cidr);
    if (!mask_str) {
        return NULL;  
    }

    ipv4_pton(AF_INET, mask_str, &mask_addr);
    free(mask_str); 

    ip_addr.s_addr &= mask_addr.s_addr;

    char* network_ip = allocate_string(INET_ADDRSTRLEN);
    if (!network_ip) {
        return NULL; 
    }

    ipv4_ntop(AF_INET, &ip_addr, network_ip, INET_ADDRSTRLEN);
    return network_ip;
}

char* calculate_broadcast_address(const char* ip, int cidr) {
    struct in_addr ip_addr, mask_addr;

    ipv4_pton(AF_INET, ip, &ip_addr);

    char* mask_str = cidr_to_mask(cidr);
    if (!mask_str) {
        return NULL;  
    }

    ipv4_pton(AF_INET, mask_str, &mask_addr);
    free(mask_str);  

    ip_addr.s_addr |= ~mask_addr.s_addr;

    char* broadcast_ip = allocate_string(INET_ADDRSTRLEN);
    if (!broadcast_ip) {
        return NULL;  
    }

    ipv4_ntop(AF_INET, &ip_addr, broadcast_ip, INET_ADDRSTRLEN);
    return broadcast_ip;
}

int calculate_number_of_hosts(int cidr) {
    return (1 << (32 - cidr)) - 2;
}

char* calculate_first_host(const char* network_ip) {
  
    char* first_host = malloc(16); 
    if (!first_host) {
        return NULL;
    }

    int octets[4];
    sscanf(network_ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);

    if (octets[3] < 255) {
        octets[3] += 1; 
    } else {
        
        octets[3] = 0;
        if (octets[2] < 255) {
            octets[2] += 1;
        } else {
            octets[2] = 0;
            if (octets[1] < 255) {
                octets[1] += 1;
            } else {
                octets[1] = 0;
                octets[0] += 1; 
            }
        }
    }

    snprintf(first_host, 16, "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
    return first_host;
}

char* calculate_last_host(const char* broadcast_ip) {
    
    char* last_host = malloc(16); 
    if (!last_host) {
        return NULL; 
    }

    int octets[4];
    sscanf(broadcast_ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);

    if (octets[3] > 0) {
        octets[3] -= 1; 
    } else {
        octets[3] = 255;
        if (octets[2] > 0) {
            octets[2] -= 1;
        } else {
            octets[2] = 255;
            if (octets[1] > 0) {
                octets[1] -= 1;
            } else {
                octets[1] = 255;
                if (octets[0] > 0) {
                    octets[0] -= 1; 
                } else {
                    free(last_host);
                    return NULL;
                }
            }
        }
    }

    snprintf(last_host, 16, "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
    return last_host;
}

char* cidr_to_mask_ipv6(int cidr) {
    struct in6_addr mask_addr = {0};
    for (int i = 0; i < cidr / 8; i++) {
        mask_addr.s6_addr[i] = 0xFF;
    }
    if (cidr % 8) {
        mask_addr.s6_addr[cidr / 8] = (0xFF << (8 - (cidr % 8)));
    }

    char* mask = malloc(INET6_ADDRSTRLEN);
    if (!mask || !ipv4_ntop(AF_INET6, &mask_addr, mask, INET6_ADDRSTRLEN)) {
        free(mask);
        return NULL;
    }
    return mask;
}

int mask_to_cidr_ipv6(const char* mask) {
    struct in6_addr mask_addr;
    if (ipv4_pton(AF_INET6, mask, &mask_addr) <= 0) {
        return -1;
    }

    int cidr = 0;
    for (int i = 0; i < 16; i++) {
        unsigned char byte = mask_addr.s6_addr[i];
        while (byte) {
            cidr += byte & 1;
            byte >>= 1;
        }
    }
    return cidr;
}

char* calculate_network_address_ipv6(const char* ip, int cidr) {
    struct in6_addr addr;
    struct in6_addr netmask;
    struct in6_addr network;

    if (ipv4_pton(AF_INET6, ip, &addr) <= 0) return NULL;

    memset(&netmask, 0, sizeof(netmask));
    for (int i = 0; i < cidr / 8; i++) {
        netmask.s6_addr[i] = 0xFF;
    }
    if (cidr % 8) {
        netmask.s6_addr[cidr / 8] = (0xFF << (8 - (cidr % 8)));
    }

    for (int i = 0; i < 16; i++) {
        network.s6_addr[i] = addr.s6_addr[i] & netmask.s6_addr[i];
    }

    char* network_ip = malloc(INET6_ADDRSTRLEN);
    if (!network_ip || !ipv4_ntop(AF_INET6, &network, network_ip, INET6_ADDRSTRLEN)) {
        free(network_ip);
        return NULL;
    }

    return network_ip;
}

char* calculate_broadcast_address_ipv6(const char* ip, int cidr) {
    struct in6_addr addr;
    struct in6_addr netmask;
    struct in6_addr broadcast;

    if (ipv4_pton(AF_INET6, ip, &addr) <= 0) return NULL;

    memset(&netmask, 0, sizeof(netmask));
    for (int i = 0; i < cidr / 8; i++) {
        netmask.s6_addr[i] = 0xFF;
    }
    if (cidr % 8) {
        netmask.s6_addr[cidr / 8] = (0xFF << (8 - (cidr % 8)));
    }

    for (int i = 0; i < 16; i++) {
        broadcast.s6_addr[i] = addr.s6_addr[i] | ~netmask.s6_addr[i];
    }

    char* broadcast_ip = malloc(INET6_ADDRSTRLEN);
    if (!broadcast_ip || !ipv4_ntop(AF_INET6, &broadcast, broadcast_ip, INET6_ADDRSTRLEN)) {
        free(broadcast_ip);
        return NULL;
    }

    return broadcast_ip;
}

char* calculate_number_of_hosts_ipv6(int cidr) {
    if (cidr < 0 || cidr > 128) {
        return NULL;  
    }

    mpz_t num_hosts;
    mpz_init(num_hosts);

    mpz_ui_pow_ui(num_hosts, 2, 128 - cidr);

    char* result_str = mpz_get_str(NULL, 10, num_hosts);

    mpz_clear(num_hosts);

    return result_str;  
}

char* calculate_first_host_ipv6(const char* network_ip) {
    
    struct in6_addr addr;
    if (ipv4_pton(AF_INET6, network_ip, &addr) <= 0) return NULL;

    addr.s6_addr[15] += 1;

    char* first_host_ip = malloc(INET6_ADDRSTRLEN);
    if (!first_host_ip || !ipv4_ntop(AF_INET6, &addr, first_host_ip, INET6_ADDRSTRLEN)) {
        free(first_host_ip);
        return NULL;
    }

    return first_host_ip;
}

char* calculate_last_host_ipv6(const char* broadcast_ip) {
    struct in6_addr addr;
    if (ipv4_pton(AF_INET6, broadcast_ip, &addr) <= 0) return NULL;

    addr.s6_addr[15] -= 1;

    char* last_host_ip = malloc(INET6_ADDRSTRLEN);
    if (!last_host_ip || !ipv4_ntop(AF_INET6, &addr, last_host_ip, INET6_ADDRSTRLEN)) {
        free(last_host_ip);
        return NULL;
    }

    return last_host_ip;
}


// --------- Funções de Super-rede e Sub-rede ---------

char* calculate_supernet(const char** networks, int num_networks) {
    struct in_addr addr;
    ipv4_pton(AF_INET, networks[0], &addr);
    addr.s_addr &= htonl(~0 << 8); 
    char* supernet = allocate_string(INET_ADDRSTRLEN);
    ipv4_ntop(AF_INET, &addr, supernet, INET_ADDRSTRLEN);
    return supernet;
}

char* divide_subnets(const char* network_ip, int cidr, int num_subnets) {
    
    int bits_needed = (int)ceil(log2(num_subnets));
    int new_cidr = cidr + bits_needed;

  
    if (new_cidr > 30) {
        return NULL; 
    }

    int total_subnets = 1 << bits_needed;  
    int hosts_per_subnet = (1 << (32 - new_cidr)) - 2; 

    size_t entry_size = INET_ADDRSTRLEN + 40; 
    size_t buffer_size = entry_size * total_subnets; 
    char* result = (char*)malloc(buffer_size);
    if (!result) {
        return NULL; 
    }
    result[0] = '\0'; 

    struct in_addr addr;
    ipv4_pton(AF_INET, network_ip, &addr);

    for (int i = 0; i < total_subnets; i++) {
        struct in_addr subnet_addr = addr;
        subnet_addr.s_addr = ntohl(ntohl(addr.s_addr) + (i * (1 << (32 - new_cidr))));

        char subnetwork[INET_ADDRSTRLEN];
        ipv4_ntop(AF_INET, &subnet_addr, subnetwork, INET_ADDRSTRLEN);

        char subnet_info[entry_size];
        snprintf(subnet_info, sizeof(subnet_info), "%s/%d [Available hosts: %d]\n", subnetwork, new_cidr, hosts_per_subnet);
        strncat(result, subnet_info, buffer_size - strlen(result) - 1);
    }

    return result;
}

// --------- Funções de Roteamento ---------

Route* routing_table = NULL; 
int num_routes = 0;          

void resize_routing_table(int new_size) {
    routing_table = realloc(routing_table, new_size * sizeof(Route));
    if (routing_table == NULL && new_size > 0) {
        fprintf(stderr, "Erro ao realocar a tabela de rotas.\n");
        exit(1);
    }
}

char* add_route(const char* destination, const char* mask, const char* gateway) {
    resize_routing_table(num_routes + 1);  
    strncpy(routing_table[num_routes].destination, destination, sizeof(routing_table[num_routes].destination));
    strncpy(routing_table[num_routes].mask, mask, sizeof(routing_table[num_routes].mask));
    strncpy(routing_table[num_routes].gateway, gateway, sizeof(routing_table[num_routes].gateway));
    num_routes++;

    char* result = malloc(100);
    snprintf(result, 100, "Route added: %s via %s with mask %s\n", destination, gateway, mask);
    return result;
}

char* remove_route(const char* destination) {
    char* result = malloc(50);
    if (!result) return NULL; 

    for (int i = 0; i < num_routes; i++) {
        if (strcmp(routing_table[i].destination, destination) == 0) {
            for (int j = i; j < num_routes - 1; j++) {
                routing_table[j] = routing_table[j + 1];
            }
            num_routes--;
            resize_routing_table(num_routes);  

            snprintf(result, 50, "Route to %s removed\n", destination);
            return result;
        }
    }
    snprintf(result, 50, "Route to %s not found\n", destination);
    return result;
}

char* print_routes() {
    size_t buffer_size = (num_routes * 100) + 30;
    char* result = malloc(buffer_size);
    if (!result) return NULL;

    if (num_routes == 0) {
        snprintf(result, buffer_size, "No routes in the table.\n");
    } else {
        strcpy(result, "Routing Table:\n");
        for (int i = 0; i < num_routes; i++) {
            char route_info[100];
            snprintf(route_info, sizeof(route_info), "Destination: %s, Mask: %s, Gateway: %s\n",
                     routing_table[i].destination,
                     routing_table[i].mask,
                     routing_table[i].gateway);
            strncat(result, route_info, buffer_size - strlen(result) - 1);
        }
    }
    return result;
}

int longest_prefix_match(const char* ip) {
    int best_match = -1;
    int longest_prefix_length = -1;

    struct in_addr ip_addr, dest_addr, mask_addr;
    if (ipv4_pton(AF_INET, ip, &ip_addr) <= 0) {
        return best_match;
    }

    for (int i = 0; i < num_routes; i++) {
        ipv4_pton(AF_INET, routing_table[i].destination, &dest_addr);
        ipv4_pton(AF_INET, routing_table[i].mask, &mask_addr);

        if ((ip_addr.s_addr & mask_addr.s_addr) == (dest_addr.s_addr & mask_addr.s_addr)) {
            int prefix_length = __builtin_popcount(mask_addr.s_addr);
            if (prefix_length > longest_prefix_length) {
                longest_prefix_length = prefix_length;
                best_match = i;
            }
        }
    }
    return best_match;
}

const char* find_route(const char* ip) {
    for (int i = 0; i < num_routes; i++) {
        struct in_addr ip_addr, dest_addr, mask_addr;

        ipv4_pton(AF_INET, ip, &ip_addr);
        ipv4_pton(AF_INET, routing_table[i].destination, &dest_addr);
        ipv4_pton(AF_INET, routing_table[i].mask, &mask_addr);

        if ((ip_addr.s_addr & mask_addr.s_addr) == (dest_addr.s_addr & mask_addr.s_addr)) {
            return routing_table[i].gateway;
        }
    }
    return NULL;
}

char* mac_to_iid(const char* mac) {
    unsigned int mac_bytes[6];

    sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", 
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], 
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
    
    mac_bytes[0] ^= 0x02;

    char* iid = malloc(24); 
    if (iid == NULL) {
        return NULL; 
    }

    sprintf(iid, "%02x%02x:%02xff:fe%02x:%02x%02x",
            mac_bytes[0], mac_bytes[1], mac_bytes[2], 
            mac_bytes[3], mac_bytes[4], mac_bytes[5]);

    return iid; 
}

uint16_t calculate_ip_checksum(const uint16_t pairs[], size_t num_pairs) {
    uint32_t sum = 0;

    for (size_t i = 0; i < num_pairs; i++) {
        
        if (i == 5) continue; 
        
        sum += pairs[i];

        while (sum >> 16) { 
            sum = (sum & 0xFFFF) + (sum >> 16); 
        }
    }

    return ~((uint16_t)sum);
}

bool verify_ip_checksum(const uint16_t pairs[], size_t num_pairs) {
    uint32_t sum = 0;

    
    for (size_t i = 0; i < num_pairs; i++) {
        sum += pairs[i];

        
        while (sum >> 16) { 
            sum = (sum & 0xFFFF) + (sum >> 16); 
        }
    }

    return (sum & 0xFFFF) == 0xFFFF; 
}


int classify_packet_priority(const char* packet) {
    if (strstr(packet, "URG") != NULL || strstr(packet, "HIGH") != NULL || strstr(packet, "PRIORITY=HIGH") != NULL) {
        return 1;
    } else if (strstr(packet, "ACK") != NULL || strstr(packet, "MEDIUM") != NULL || strstr(packet, "PRIORITY=MEDIUM") != NULL) {
        return 2;
    } else if (strstr(packet, "DATA") != NULL || strstr(packet, "LOW") != NULL || strstr(packet, "PRIORITY=LOW") != NULL) {
        return 3;
    } else {
        return 4;
    }
}


// --------- Funções de Diagnóstico de Rede ---------

void ping(const char* ip) {
    
    char command[100];

    #ifdef _WIN32
        snprintf(command, sizeof(command), "ping -n 4 %s", ip); 
    #else
        snprintf(command, sizeof(command), "ping -c 4 %s", ip); 
    #endif

    system(command);
}

void tracert(const char* ip) {
    
    char command[100];

    #ifdef _WIN32
        snprintf(command, sizeof(command), "tracert /h 5 %s", ip); 
    #else
        snprintf(command, sizeof(command), "traceroute -m 5 %s", ip); 
    #endif

    system(command);
}

// --------- Funções de Validação ---------

bool validate_ip(const char* ip) {
    int octet;
    char extra;

    if (sscanf(ip, "%d.%d.%d.%d%c", &octet, &octet, &octet, &octet, &extra) == 4) {
        int parts[4];
        sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]);
        for (int i = 0; i < 4; i++) {
            if (parts[i] < 0 || parts[i] > 255) return false;
        }
        return true;
    }
    return false;
}

bool validate_ipv6(const char* ipv6) {
    struct in6_addr result;
    return ipv4_pton(AF_INET6, ipv6, &result) == 1;
}

bool validate_cidr(int prefix_length) {
    return prefix_length >= 0 && prefix_length <= 128;
}

bool validate_mask(const char* mask) {
    int parts[4];

    if (sscanf(mask, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) == 4) {
        int valid_masks[] = {255, 254, 252, 248, 240, 224, 192, 128, 0};
        for (int i = 0; i < 4; i++) {
            bool valid = false;
            for (int j = 0; j < 9; j++) {
                if (parts[i] == valid_masks[j]) {
                    valid = true;
                    break;
                }
            }
            if (!valid) return false;
        }
        return true;
    }
    return false;
}

bool validate_mac(const char* mac) {
    int values[6];
    char extra;

    if (sscanf(mac, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &extra) == 6) {
        return true;
    }
    return false;
}