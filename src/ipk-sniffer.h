/**
 * @file    ipk-sniffer.h
 * @brief   Definitions and libraries for ipk-sniffer.c
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-04-09
*/

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>
#include <math.h>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>      // Ethernet, ARP
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>    // ICMP, IPv4
#include <netinet/ip6.h>        // IPv6
#include <netinet/tcp.h>        // TCP
#include <netinet/udp.h>        // UDP

// Size for allocations
#define TOS_LENGHT 5
#define DATE_LENGHT 20
#define TIMESTAMP_LENGHT 30
#define IPV4_ADDRESS_LENGHT 16
#define IPV6_ADDRESS_LENGHT 40
#define MAC_ADDRESS_LENGHT 18
#define MAX_PACKET_FILTER_LENGHT 50

// Constants for program usage
#define TIMEOUT_IN_MS 1000
#define SNAPSHOT_LENGHT 1518
#define IP_ADDRESS_LENGHT_IN_BYTES 4
#define WORDS2BYTES_SIZE 4          // In header is stored only 4 bit number that specify number of 32-bit words

// Error codes constants
#define PROCESS_ABORTED 9
#define INVALID_ARGUMENT 10
#define PCAP_FUNCTION_FAILED 11
#define INTERNAL_ERROR 99           // Allocation failed or failed to open file

// Protocol types
#define IPV4_PROTOCOL 0x0800
#define IPV6_PROTOCOL 0x86DD
#define ARP_PROTOCOL  0x0806

#define ICMP_PROTOCOL 0x01
#define TCP_PROTOCOL  0x06
#define UDP_PROTOCOL  0x11
#define ICMPV6_PROTOCOL 0x3A


// Contains arguments informations
typedef struct args
{
    char *interface_name;
    int port_number;
    int packet_cnt;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;
} args_t;

/**
 * @brief Prints help, hint how to use ipk-sniffer
 * 
*/
void print_help();

/**
 * @brief Converts string to integer, check if conversion is successful
 * 
 * @param number Number to convert
 * @param error_message Additional information to add to error message
 * @return Converted number, in case of failure, exits the program
*/
int convert_string2int(char *number, const char *error_message);

/**
 * @brief Get allocated list of all active network interfaces
 * 
 * @param interfaces_list List to store the interface
*/
void get_all_interfaces(pcap_if_t **interfaces_list);

/**
 * @brief Prints all active network intefaces
 * 
*/
void print_all_interfaces();

/**
 * @brief Check if given interface is in the list of all active network interfaces
 * 
 * @return True, whether interface name is valid, otherwise false
*/
bool is_valid_interface(char *interface_name);

/**
 * @brief Parse arguments
 * 
 * @param argc Number of arguments
 * @param argv Program arguments
 * @return Pointer to structure args_t* with loaded values
*/
args_t *parse_arguments(int argc, char **argv);

/**
 * @brief Handle signal Ctrl+C and other system interrupt signal, to exit program safely without any memory leaks
 * 
 * @param sig Integer designation of system interrupt signal
*/
void handle_sigint(int sig);

/**
 * @brief Prints out data in lines, where each line is composited of the offset
 *        of printed bytes, then data in hexadecimal form and data in ascii
 * 
 * @param data Data which packet was containing
 * @param offset Offset from which data is printed
 * @param data_len Lenght of data in bytes
*/
void dump_data(const u_char *data, int offset, int data_len);

/**
 * @brief Get timestamp with right format for printing
 * 
 * @param frame_header Pointer to whole frame header
 * @param timestamp_buffer Buffer to store loaded timestamp
*/
void get_timestamp(const struct pcap_pkthdr *frame_header, char *timestamp_buffer);

/**
 * @brief Get mac address with right format for printing
 * 
 * @param eth_host Array of numbers, which representate mac address
 * @param mac_address_buffer Buffer to store loaded mac address
*/
void get_mac_address(uint8_t *eth_host, char *mac_address_buffer);

/**
 * @brief Get IPv4 address with right format for printing
 * 
 * @param ip_address_number Number, which representate IPv4 address
 * @param ip_address_buffer Buffer to store loaded IPv4 address
*/
void get_ipv4_address(uint32_t ip_address_number, char *ip_address_buffer);

/**
 * @brief Main function, that process all of the catched packets
 * 
 * @param user User arguments
 * @param frame_header Frame header storing basic informations about packet
 * @param packet Data of catched packet
*/
void callback(u_char *user, const struct pcap_pkthdr *frame_header, const u_char *packet);

/**
 * @brief Creates a filter of packets, based on program input arguments 
 * 
 * @param args Program input arguments.
 * @param packet_filter_string Buffer to store created packet filter
*/
void create_packet_filter(args_t *args, char *packet_filter_string);

#endif

/** End of file ipk-sniffer.h **/
