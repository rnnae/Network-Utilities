#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Funções de conversão IPv4, IPv6 e resumo de IPv6
char* decimal_to_binary(int decimal);
int binary_to_decimal(const char* binary_str);
char* hexadecimal_to_binary(const char* hex_str);
char* binary_to_hexadecimal(const char* binary_str);
char* decimal_to_hexadecimal(int decimal);
int hexadecimal_to_decimal(const char* hex_str);
char* ip_to_binary(const char* ip);
char* binary_to_ip(const char* binary_str);
char* ipv6_to_binary(const char* ipv6);
char* binary_to_ipv6(const char* binary_str);
char* summarize_ipv6(const char* ipv6);

// Operações de CIDR e máscaras
char* cidr_to_mask(int cidr);
int mask_to_cidr(const char* mask);
char* calculate_network_address(const char* ip, int cidr);
char* calculate_broadcast_address(const char* ip, int cidr);
int calculate_number_of_hosts(int cidr);
char* calculate_first_host(const char* network_ip);
char* calculate_last_host(const char* broadcast_ip);
char* cidr_to_mask_ipv6(int cidr);
int mask_to_cidr_ipv6(const char* mask);
char* calculate_network_address_ipv6(const char* ip, int cidr);
char* calculate_broadcast_address_ipv6(const char* ip, int cidr);
char* calculate_number_of_hosts_ipv6(int cidr);
char* calculate_first_host_ipv6(const char* network_ip);
char* calculate_last_host_ipv6(const char* broadcast_ip);

// Funções de super-rede e sub-rede
char* calculate_supernet(const char** networks, int num_networks);
char* divide_subnets(const char* network_ip, int cidr, int num_subnets);

// Funções de roteamento
typedef struct {
    char destination[16];
    char mask[16];
    char gateway[16];
} Route;

extern Route* routing_table;  
extern int num_routes;

void resize_routing_table(int new_size);
char* add_route(const char* destination, const char* mask, const char* gateway);
char* remove_route(const char* destination);
char* print_routes();
const char* find_route(const char* ip);
int longest_prefix_match(const char* ip);

// Funções de análise de tráfego
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

char* mac_to_iid(const char* mac);
uint16_t calculate_ip_checksum(const uint16_t pairs[], size_t num_pairs);
bool verify_ip_checksum(const uint16_t pairs[], size_t num_pairs);
int classify_packet_priority(const char* packet);

// Funções de diagnóstico de rede
void ping(const char* ip);
void tracert(const char* ip);

// Funções de validação
bool validate_ip(const char* ip);
bool validate_ipv6(const char* ipv6);
bool validate_cidr(int prefix_length);
bool validate_mask(const char* mask);
bool validate_mac(const char* mac);


#endif // NETWORK_UTILS_H