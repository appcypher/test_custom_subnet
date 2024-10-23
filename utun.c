// create_multiple_utun_with_handler.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <fcntl.h>
#include <pthread.h>  // Included pthread.h for threading functions

#define MAX_UTUN 10
#define BUFFER_SIZE 4096

// Structure to hold utun interface information
typedef struct {
    int fd;
    char ifname[IFNAMSIZ];
} utun_interface;

// Global array to store created utun interfaces
utun_interface utun_interfaces[MAX_UTUN];
int utun_count = 0;

// Signal handler to gracefully close all utun interfaces
void handle_signal(int sig) {
    for (int i = 0; i < utun_count; i++) {
        if (utun_interfaces[i].fd != -1) {
            close(utun_interfaces[i].fd);
            printf("\nClosed %s.\n", utun_interfaces[i].ifname);
        }
    }
    exit(0);
}

// Function to create a utun interface and return its file descriptor
int create_utun_interface(char* iface_name) {
    int fd;
    struct sockaddr_ctl sc;
    struct ctl_info ci;
    char ifname[IFNAMSIZ];
    socklen_t ifname_len = sizeof(ifname);

    // Open a control socket
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    // Specify the utun control name
    memset(&ci, 0, sizeof(ci));
    strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name)-1);

    // Get control ID
    if (ioctl(fd, CTLIOCGINFO, &ci) == -1) {
        perror("ioctl CTLIOCGINFO");
        close(fd);
        return -1;
    }

    // Setup sockaddr_ctl structure
    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ci.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0; // 0 to get the next available utun interface

    // Connect to the utun control
    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
        perror("connect");
        close(fd);
        return -1;
    }

    // Retrieve the interface name
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == -1) {
        perror("getsockopt UTUN_OPT_IFNAME");
        close(fd);
        return -1;
    }

    strncpy(iface_name, ifname, IFNAMSIZ-1);
    iface_name[IFNAMSIZ-1] = '\0';

    printf("Created interface: %s\n", iface_name);
    return fd;
}

// Function to assign an IP address to the utun interface
int assign_ip_address(const char* iface, const char* local_ip, const char* remote_ip, const char* netmask) {
    char command[256];
    // Construct the ifconfig command with both local and remote IPs
    snprintf(command, sizeof(command), "ifconfig %s %s %s netmask %s up", iface, local_ip, remote_ip, netmask);

    printf("Executing: %s\n", command);
    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "Failed to assign IP address %s -> %s to interface %s\n", local_ip, remote_ip, iface);
        return -1;
    }
    return 0;
}


// Function to process packets
void process_packet(int fd, unsigned char *buffer, ssize_t nbytes) {
    // Ensure we have at least the 4-byte header
    if (nbytes < 4) {
        fprintf(stderr, "Packet too small\n");
        return;
    }

    // Extract the protocol family
    uint32_t proto_family_net = *(uint32_t *)buffer; // Network byte order
    uint32_t proto_family = ntohl(proto_family_net); // Host byte order

    // Point to the actual packet data
    unsigned char *packet = buffer + 4;
    ssize_t packet_len = nbytes - 4;

    // For demonstration, we'll echo back the packet
    // Reconstruct the buffer with the protocol header
    unsigned char write_buffer[BUFFER_SIZE];

    // Set the protocol family in network byte order
    *(uint32_t *)write_buffer = proto_family_net;

    // Copy the packet data
    memcpy(write_buffer + 4, packet, packet_len);

    ssize_t nwritten = write(fd, write_buffer, packet_len + 4);
    if (nwritten < 0) {
        perror("write");
    } else {
        // Uncomment to see the echoed packet size
        // printf("Echoed packet of %zd bytes\n", nwritten);
    }
}

// Thread function to handle packets on a utun interface
void* utun_packet_handler(void* arg) {
    utun_interface* iface = (utun_interface*)arg;
    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        ssize_t nbytes = read(iface->fd, buffer, sizeof(buffer));
        if (nbytes < 0) {
            perror("read");
            break;
        }

        // Uncomment the line below to see received packet sizes
        // printf("%s: Received packet of %zd bytes\n", iface->ifname, nbytes);

        // Process the packet
        process_packet(iface->fd, buffer, nbytes);
    }

    close(iface->fd);
    iface->fd = -1;
    return NULL;
}

int main(int argc, char *argv[]) {
    // Register signal handlers for graceful termination
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <number_of_utun_interfaces>\n", argv[0]);
        fprintf(stderr, "Example: %s 3\n", argv[0]);
        return EXIT_FAILURE;
    }

    int num_utun = atoi(argv[1]);
    if (num_utun < 1 || num_utun > MAX_UTUN) {
        fprintf(stderr, "Please specify a number between 1 and %d.\n", MAX_UTUN);
        return EXIT_FAILURE;
    }

    // Create specified number of utun interfaces
    for (int i = 0; i < num_utun; i++) {
        char iface_name[IFNAMSIZ];
        int fd = create_utun_interface(iface_name);
        if (fd == -1) {
            fprintf(stderr, "Failed to create utun interface %d.\n", i);
            continue;
        }

        // Store interface info
        utun_interfaces[utun_count].fd = fd;
        strncpy(utun_interfaces[utun_count].ifname, iface_name, IFNAMSIZ-1);
        utun_interfaces[utun_count].ifname[IFNAMSIZ-1] = '\0';
        utun_count++;

        // Assign IP addresses
        // For simplicity, assign sequential subnets: 10.0.i.1 (local) and 10.0.i.2 (remote)
        char local_ip[16];
        char remote_ip[16];
        char netmask[16] = "255.255.255.0";

        snprintf(local_ip, sizeof(local_ip), "10.0.%d.1", i);
        snprintf(remote_ip, sizeof(remote_ip), "10.0.%d.2", i);

        if (assign_ip_address(iface_name, local_ip, remote_ip, netmask) != 0) {
            fprintf(stderr, "Failed to assign IP to interface %s.\n", iface_name);
            close(fd);
            utun_interfaces[utun_count - 1].fd = -1;
            continue;
        }

        printf("Assigned %s -> %s to %s.\n", local_ip, remote_ip, iface_name);
    }

    printf("All specified utun interfaces have been created and configured.\n");
    printf("They are active. Press Ctrl+C to terminate and remove them.\n");

    // Start packet handlers for each interface
    for (int i = 0; i < utun_count; i++) {
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, utun_packet_handler, (void*)&utun_interfaces[i]) != 0) {
            perror("pthread_create");
            continue;
        }
        // Detach the thread as we don't need to join later
        pthread_detach(thread_id);
    }

    // Keep the program running to maintain the utun interfaces
    while (1) {
        sleep(1);
    }

    // Cleanup (unreachable in this example)
    handle_signal(0);

    return EXIT_SUCCESS;
}
