/**
 * @file    ipk-sniffer.c
 * @brief   IPK - project 2, variant ZETA
 * @author  David Drtil <xdrtil03@stud.fit.vutbr.cz>
 * @date    2022-04-09
*/

#include "ipk-sniffer.h"

void print_help()
{
    printf("Packet sniffer\n");
    printf("The network analyzer that is capable of capturing and filtering packets on a the network interface.\n");
    printf("Usage: \n");
    printf("    ipk-sniffer [-i interface | --interface interface] [OPTIONS...]\n");
    printf("    ipk-sniffer [-h | --help]\n");
    printf("Required argument:\n");
    printf("    -i <interface> | --interface <interface>  One interface to listen to.\n");
    printf("                                              If this argument or its value is not set,\n");
    printf("                                              all active interfaces are listed out.\n");
    printf("Optional arguments:\n");
    printf("These arguments can be arbitrarily combined.\n");
    printf("    -p <port_number>                          Filter packets on the specific interface by port.\n");
    printf("                                              If this argument not set, all ports are considered.\n");
    printf("    -n <packet_number>                        Display only given number of packets.\n");
    printf("    --tcp | -t                                Display only TCP packets.\n");
    printf("    --udp | -u                                Display only UDP packets.\n");
    printf("    --arp                                     Display only ARP frames.\n");
    printf("    --icmp                                    Display only ICMPv4 and ICMPv6 packets.\n");
    printf("Help:\n");
    printf("    -h | --help                               Prints this help and exit program.\n\n");
}

int convert_string2int(char *number, const char *error_message)
{
    char *invalid_part;
    int converted_number = (int)strtol(number, &invalid_part, 10); 
    if (*invalid_part != '\0')
    {
        fprintf(stderr, "%s Failed to convert number \'%s\'.\n", error_message, number);
        exit(INVALID_ARGUMENT);
    }
    return converted_number;
}

void get_all_interfaces(pcap_if_t **interfaces_list)
{
    char error_message[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(interfaces_list, error_message) == -1)
    {
        fprintf(stderr, "Function pcap_findalldevs failed, error message is: \'%s\'.\n", error_message);
        exit(PCAP_FUNCTION_FAILED);
    }
}

void print_all_interfaces()
{
    pcap_if_t *interfaces_list = NULL;
    get_all_interfaces(&interfaces_list);

    printf("List of all interfaces: \n");
    for (pcap_if_t *interface = interfaces_list; interface != NULL; interface = interface->next)
    {
        printf("%s\n", interface->name);
    }

    pcap_freealldevs(interfaces_list);
}

bool is_valid_interface(char *interface_name)
{
    pcap_if_t *interfaces_list = NULL;
    get_all_interfaces(&interfaces_list);

    for(pcap_if_t *interface = interfaces_list; interface != NULL; interface = interface->next)
    {
        if(!strcmp(interface->name, interface_name))
        {
            pcap_freealldevs(interfaces_list);
            return true;
        }
    }
    
    pcap_freealldevs(interfaces_list);
    return false;
}

args_t *parse_arguments(int argc, char **argv)
{
    if (argc == 2)
    {
        // Print Help
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
        {
            print_help();
            exit(EXIT_SUCCESS);
        }
    }

    // Create structure and set default values
    args_t *args = (args_t *)malloc(sizeof(struct args));
    if (args == NULL)
    {
        fprintf(stderr, "Allocation of struct args_t failed.\n");
        exit(INTERNAL_ERROR);
    }
    args->interface_name = NULL;
    args->port_number = -1;     // Value -1 means not set port
    args->packet_cnt = 1;       // Default value is 1
    args->tcp = false;
    args->udp = false;
    args->arp = false;
    args->icmp = false;

    // Parse all arguments
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface"))
        {
            int interface_name_idx = i + 1;
            if (interface_name_idx < argc)
            {
                if (argv[interface_name_idx][0] == '-')
                {
                    // Interface name is missing, at interface_name_idx is next argument
                    continue;
                }
                int interface_name_lenght = strlen(argv[interface_name_idx]);
                args->interface_name = (char *)malloc(interface_name_lenght + 1);
                if (args->interface_name == NULL)
                {
                    fprintf(stderr, "Allocation of args->interface_name failed.\n");
                    exit(INTERNAL_ERROR);
                }
                strncpy(args->interface_name, argv[interface_name_idx], interface_name_lenght);
                args->interface_name[interface_name_lenght] = '\0';

                if (!is_valid_interface(args->interface_name))
                {
                    fprintf(stderr, "Interface \'%s\' was not found.\n", args->interface_name);
                    exit(INVALID_ARGUMENT);
                }
                i++;
            }
        }
        else if (!strcmp(argv[i], "-p"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -p is missing port number.\n");
                exit(INVALID_ARGUMENT);
            }
            args->port_number = convert_string2int(argv[i + 1], "Invalid argument of -p, it has wrong port number.");
            if (args->port_number < 0 || args->port_number > 65535)
            {
                fprintf(stderr, "Port number cannot be lower than 0 or bigger than 65535.\n");
                exit(INVALID_ARGUMENT);
            }
            i++;
        }
        else if (!strcmp(argv[i], "-n"))
        {
            if (i + 1 == argc)
            {
                fprintf(stderr, "Not enough arguments, argument -n is missing number of packets to display.\n");
                exit(INVALID_ARGUMENT);
            }
            args->packet_cnt = convert_string2int(argv[i + 1], "Invalid argument of -n, it has wrong number of packets.");
            if (args->packet_cnt < 1)
            {
                fprintf(stderr, "Packet number to display cannot be lower than 1.\n");
                exit(INVALID_ARGUMENT);
            }
            i++;
        }
        else if (!strcmp(argv[i], "--tcp") || !strcmp(argv[i], "-t"))
        {
            args->tcp = true;
        }
        else if (!strcmp(argv[i], "--udp") || !strcmp(argv[i], "-u"))
        {
            args->udp = true;
        }
        else if (!strcmp(argv[i], "--arp"))
        {
            args->arp = true;
        }
        else if (!strcmp(argv[i], "--icmp"))
        {
            args->icmp = true;
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            fprintf(stderr, "Invalid argument help. To print help, no other arguments cannot be set.\n");
            exit(INVALID_ARGUMENT);
        }
        else
        {
            fprintf(stderr, "Invalid argument \'%s\'.\n", argv[i]);
            exit(INVALID_ARGUMENT);
        }
    }

    // Certain protocol filter was not set, display packet from all protocols
    if (!(args->tcp || args->udp || args->arp || args->icmp))
    {
        args->tcp = true;
        args->udp = true;
        args->arp = true;
        args->icmp = true;
    }

    // Port number was given, so packet must be sniffed from transtort layer protocols
    if (args->port_number != -1 && !args->tcp && !args->udp)
    {
        args->tcp = true;
        args->udp = true;
    }
    return args;
}

// Handler for SIGINT, catched Ctrl+C inputed from keyboard
void handle_sigint(int sig)
{
    printf("\nProccess terminated. Caught signal %d (ctrl + c).\n", sig);
    exit(PROCESS_ABORTED);
}

void dump_data(const u_char *data, int offset, int data_len)
{
    int low_offset = offset / 16;
    int high_offset = (offset + data_len + 15) / 16;
    printf("\n");
    for (int o = low_offset; o < high_offset; o++)
    {
        int row_offset = o << 4;
        printf("0x%04X:  ", row_offset);
        for (int i = 0; i < 16; i++)
        {
            if (i > 0)
            {
                printf(" ");
            }
            if (i == 8)
            {
                printf(" ");
            }
            if (i + row_offset < offset || i + row_offset >= offset + data_len)
            {
                printf("  ");
            }
            else
            {
                char pair_of_hex_numbers[3];
                sprintf(pair_of_hex_numbers, "%02X", data[i + row_offset]);
                pair_of_hex_numbers[0] = tolower(pair_of_hex_numbers[0]);
                pair_of_hex_numbers[1] = tolower(pair_of_hex_numbers[1]);
                pair_of_hex_numbers[2] = '\0';
                printf("%s", pair_of_hex_numbers);
            }
        }
        printf("  ");
        for (int i = 0; i < 16; i++)
        {
            if (i == 8)
            {
                printf(" ");
            }
            if (i + row_offset < offset || i + row_offset >= offset + data_len)
            {
                printf(" ");
            }
            else if (data[i + row_offset] <= 31 || data[i + row_offset] >= 128)
            {
               printf(".");
            }
            else
            {
                printf("%c", data[i + row_offset]);
            }
        }
        printf("\n");
    }
}

void get_timestamp(const struct pcap_pkthdr *frame_header, char *timestamp_buffer)
{
    const struct timeval *tv = &frame_header->ts;
    struct tm *gt = localtime(&tv->tv_sec);
    int ms = (tv->tv_usec) / 1000;
    int offset = gt->tm_gmtoff / 60;

    // Change sign of offset (zone)
    char sign = '+';
    if(offset < 0)
    {
        sign = '-';
        offset = -offset;
    }
    
    // Load string with timestamp
    char date[DATE_LENGHT];
    strftime(date, DATE_LENGHT, "%Y-%m-%dT%H:%M:%S", gt);
    sprintf(timestamp_buffer, "%s.%03d%c%02d:%02d", date, ms, sign, offset / 60, offset % 60);
}

void get_mac_address(uint8_t *eth_host, char *mac_address_buffer)
{
    for (int i = 0; i < ETH_ALEN; i++)
    {
        if (i > 0)
        {
            strcat(mac_address_buffer, ":");
        }
        char pair_of_hex_numbers[3];
        sprintf(pair_of_hex_numbers, "%02X", eth_host[i]);
        pair_of_hex_numbers[0] = tolower(pair_of_hex_numbers[0]);
        pair_of_hex_numbers[1] = tolower(pair_of_hex_numbers[1]);
        pair_of_hex_numbers[2] = '\0';

        strcat(mac_address_buffer, pair_of_hex_numbers);
    }
    mac_address_buffer[MAC_ADDRESS_LENGHT - 1] = '\0';
}

void get_ipv4_address(uint32_t ip_address_number, char *ip_address_buffer)
{
    for (int i = 0; i < IP_ADDRESS_LENGHT_IN_BYTES; i++)
    {
        if (i > 0)
        {
            strcat(ip_address_buffer, ".");
        }
        char tmp[4];
        sprintf(tmp, "%d", ((u_char *)(&ip_address_number))[i]);
        strcat(ip_address_buffer, tmp);
    }
    ip_address_buffer[IPV4_ADDRESS_LENGHT - 1] = '\0';
}

void callback(u_char *user, const struct pcap_pkthdr *frame_header, const u_char *packet)
{
    // Print basic informations from the frame
    struct ether_header *eth_header = (struct ether_header *)packet;
    char frame_timestamp[TIMESTAMP_LENGHT] = {'\0'};
    get_timestamp(frame_header, frame_timestamp);
    printf("timestamp: %s\n", frame_timestamp);
    
    char src_mac_address[MAC_ADDRESS_LENGHT] = {'\0'};
    get_mac_address(eth_header->ether_shost, src_mac_address);
    printf("src MAC: %s\n", src_mac_address);

    char dst_mac_address[MAC_ADDRESS_LENGHT] = {'\0'};
    get_mac_address(eth_header->ether_dhost, dst_mac_address);
    printf("dst MAC: %s\n", dst_mac_address);

    printf("frame lenght: %d bytes\n", frame_header->caplen);

    // Process packet depending on the protocol type
    int ethernet_type = ntohs(eth_header->ether_type);
    if (ethernet_type == IPV4_PROTOCOL)
    {
        // Process IP addresses
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip_address[IPV4_ADDRESS_LENGHT] = {'\0'};
        get_ipv4_address(ip_header->ip_src.s_addr, src_ip_address);
        printf("src IP: %s\n", src_ip_address);
        
        char dst_ip_address[IPV4_ADDRESS_LENGHT] = {'\0'};
        get_ipv4_address(ip_header->ip_dst.s_addr, dst_ip_address);
        printf("dst IP: %s\n", dst_ip_address);

        // For reading data from packet
        int data_offset = sizeof(struct ether_header) + ip_header->ip_hl * WORDS2BYTES_SIZE;
        int data_len = frame_header->caplen - data_offset;
        const u_char *data = packet + data_offset;

        // Resolve protocol
        int ip_protocol = ip_header->ip_p;
        if (ip_protocol == ICMP_PROTOCOL)
        {
            printf("type of service: ICMP (IPv4)\n");
            dump_data(packet, data_offset, data_len);
            // dump_data(packet + data_offset, 0, data_len);     // Alternative output
        }
        else if (ip_protocol == TCP_PROTOCOL)
        {
            struct tcphdr *tcp_header = (struct tcphdr *)data;
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            printf("type of service: TCP (IPv4)\n");
            dump_data(packet, data_offset, data_len);
        }
        else if (ip_protocol == UDP_PROTOCOL)
        {
            struct udphdr *udp_header = (struct udphdr *)data;
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            printf("type of service: UDP (IPv4)\n");
            dump_data(packet, data_offset, data_len);
        }
    }
    else if (ethernet_type == IPV6_PROTOCOL)    // IPv6
    {
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

        char src_ip_address[IPV6_ADDRESS_LENGHT] = {'\0'};
        inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_ip_address, NI_MAXHOST);
        printf("src IP: %s\n", src_ip_address);

        char dst_ip_address[IPV6_ADDRESS_LENGHT] = {'\0'};
        inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_ip_address, NI_MAXHOST);
        printf("dst IP: %s\n", dst_ip_address);

        // For reading data from packet
        int data_offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr);
        int data_len = frame_header->caplen - data_offset;
        const u_char *data = packet + data_offset;

        // Resolve protocol
        int ipv6_protocol = ipv6_header->ip6_nxt;
        if (ipv6_protocol == ICMP_PROTOCOL || ipv6_protocol == ICMPV6_PROTOCOL)
        {
            printf("type of service: ICMP (IPv6)\n");
            dump_data(packet, data_offset, data_len);
        }
        else if (ipv6_protocol == TCP_PROTOCOL)
        {
            struct tcphdr *tcp_header = (struct tcphdr *)data;
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            printf("type of service: TCP (IPv6)\n");
            dump_data(packet, data_offset, data_len);
        }
        else if (ipv6_protocol == UDP_PROTOCOL)
        {
            struct udphdr *udp_header = (struct udphdr *)data;
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            printf("type of service: UDP (IPv6)\n");
            dump_data(packet, data_offset, data_len);
        }
    }
    else if (ethernet_type == ARP_PROTOCOL)    // ARP
    {
        struct arphdr *arp_header = (struct arphdr *)(packet + sizeof(struct ether_header));
        int data_offset = sizeof(struct ether_header) + sizeof(struct arphdr);
        int data_len = frame_header->caplen - data_offset;
        uint8_t *data = (uint8_t *)packet + data_offset;

        if (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER)
        {
            char src_mac_address[MAC_ADDRESS_LENGHT] = {'\0'};
            get_mac_address(data, src_mac_address);
            printf("src MAC: %s\n", src_mac_address);

            char dst_mac_address[MAC_ADDRESS_LENGHT] = {'\0'};
            get_mac_address(data + arp_header->ar_hln + arp_header->ar_pln, dst_mac_address);
            printf("dst MAC: %s\n", dst_mac_address);

            char src_ip_address[IPV4_ADDRESS_LENGHT] = {'\0'};
            get_ipv4_address(*(uint32_t *)(data + arp_header->ar_hln), src_ip_address);
            printf("src IP: %s\n", src_ip_address);

            char dst_ip_address[IPV4_ADDRESS_LENGHT] = {'\0'};
            get_ipv4_address(*(uint32_t *)(data + arp_header->ar_hln + arp_header->ar_pln + arp_header->ar_hln), dst_ip_address);
            printf("dst IP: %s\n", dst_ip_address);
        }
        printf("type of service: ARP\n");
        dump_data(packet, data_offset, data_len);
    }
}

void create_packet_filter(args_t *args, char *packet_filter_string)
{
    if(args->port_number != -1)
    {
        sprintf(packet_filter_string, "port %d and ", args->port_number);
    }

    bool is_first_protocol = true;
    if (args->icmp)
    {
        if (!is_first_protocol)
        {
            strcat(packet_filter_string, " or ");
        }
        strcat(packet_filter_string, "icmp");
        is_first_protocol = false;
    }
    if (args->tcp)
    {
        if (!is_first_protocol)
        {
            strcat(packet_filter_string, " or ");
        }
        strcat(packet_filter_string, "tcp");
        is_first_protocol = false;
    }
    if (args->udp)
    {
        if (!is_first_protocol)
        {
            strcat(packet_filter_string, " or ");
        }
        strcat(packet_filter_string, "udp");
        is_first_protocol = false;
    }
    if (args->arp)
    {
        if (!is_first_protocol)
        {
            strcat(packet_filter_string, " or ");
        }
        strcat(packet_filter_string, "arp");
        is_first_protocol = false;
    }
}

int main(int argc, char **argv)
{
    args_t *args = parse_arguments(argc, argv);
    if (args->interface_name == NULL)
    {
        // All active interfaces are listed out
        print_all_interfaces();
        free(args);
        exit(EXIT_SUCCESS);
    }

    // Treat of signal Ctrl+C, to exit program safely 
    signal(SIGINT, handle_sigint);

    // Obtain network mask and number
    bpf_u_int32 ip_address_of_network;
    bpf_u_int32 network_mask;
    char error_message[PCAP_ERRBUF_SIZE];
    int pcap_lookupnet_error = pcap_lookupnet(args->interface_name, &ip_address_of_network, &network_mask, error_message);
    if (pcap_lookupnet_error != 0)
    {
        fprintf(stderr, "Pcap_lookupnet failed to find network mask with error code %d.\n", pcap_lookupnet_error);
        fprintf(stderr, "Error message: \'%s\'\n", error_message);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Obtain the handle on inteface for read
    pcap_t *interface_handle = pcap_open_live(args->interface_name, SNAPSHOT_LENGHT, 1, TIMEOUT_IN_MS, error_message);
    if (interface_handle == NULL)
    {
        fprintf(stderr, "Pcap_open_live failed to open interface.\n");
        fprintf(stderr, "Error message: \'%s\'\n", error_message);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Create filter of packets
    char packet_filter_string[MAX_PACKET_FILTER_LENGHT] = {'\0'};
    create_packet_filter(args, packet_filter_string);

    // Check and recompile the filter of packets
    struct bpf_program packet_filter;
    int pcap_compile_error = pcap_compile(interface_handle, &packet_filter, packet_filter_string, 0, ip_address_of_network);
    if (pcap_compile_error != 0)
    {
        char *filter_error_message = pcap_geterr(interface_handle);
        fprintf(stderr, "Pcap_compile failed to compile filter \'%s\' with error code %d.\n", packet_filter_string, pcap_compile_error);
        fprintf(stderr, "Error message: \'%s\'\n", filter_error_message);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Set the filter of packets
    int pcap_setfilter_error = pcap_setfilter(interface_handle, &packet_filter);
    if (pcap_setfilter_error != 0)
    {
        char *setfilter_error_message = pcap_geterr(interface_handle);
        fprintf(stderr, "Pcap_setfilter failed to set filter \'%s\' with error code %d.\n", packet_filter_string, pcap_setfilter_error);
        fprintf(stderr, "Error message: \'%s\'\n", setfilter_error_message);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Catch and process the packets
    int pcap_loop_error = pcap_loop(interface_handle, args->packet_cnt, callback, NULL);
    if (pcap_loop_error != 0)
    {
        char *loop_error_message = pcap_geterr(interface_handle);
        fprintf(stderr, "pcap_loop failed with error code %d.\n", pcap_loop_error);
        fprintf(stderr, "Error message: \'%s\'\n", loop_error_message);
        exit(PCAP_FUNCTION_FAILED);
    }

    // Sniffing of packets are done, handle to the interface to listen is closed
    pcap_close(interface_handle);

    // Free alocated structure
    free(args->interface_name);
    free(args);

    return 0;
}

/** End of file ipk-sniffer.c **/
