#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    // Declare variables
    FILE* file_name;
    unsigned char readByte;
    int count = 0;
    int errorCode = 0;
    int ihl = 0;
    int ecn = 0;
    int total_length = 0;
    int identification = 0;
    int flags = 0;
    int fragment_offset = 0;
    int source_port = 0;
    int dest_port = 0;
    int checksum = 0;
    int data_offset = 0;
    int tcp_checksum = 0;
    int urgent_pointer = 0;
    int window_size = 0;
    int option_words = 0;
    int tcp_options = 0;

    // Open the binary file for reading
    if (argc < 2) {
        printf("Error, no filename was provided.");
        errorCode = 1;
    }
    else {
        file_name = fopen(argv[1], "rb");
        if (file_name == NULL) {
            printf("%s %s", argv[1], "Not able to find a file.");
            errorCode = 2;
        }
        else {
            // Print Ethernet Header
            printf("Ethernet Header:\n");
            printf("----------------\n");

            // Read and print destination MAC address
            printf("Destination MAC Address:\t\t");
            fread(&readByte, 1, 1, file_name);
            for (int i = 0; i < 5; i++) {
                printf("%02x:", readByte);
                fread(&readByte, 1, 1, file_name);
            }
            printf("%02x\n", readByte);

            // Read and print source MAC address
            printf("Source MAC Address:\t\t\t");
            fread(&readByte, 1, 1, file_name);
            for (int i = 0; i < 5; i++) {
                printf("%02x:", readByte);
                fread(&readByte, 1, 1, file_name);
            }
            printf("%02x\n", readByte);

            // Read and print Type
            printf("Type:\t\t\t\t\t");
            fread(&readByte, 1, 1, file_name);
            printf("%02x", readByte);
            fread(&readByte, 1, 1, file_name);
            printf("%02x\n", readByte);

            // Start reading the IP header
            printf("\nIPv4 Header:\n");
            printf("------------\n");

            // Read and print Version and Internet Header Length
            fread(&readByte, 1, 1, file_name);
            printf("Version:\t\t\t\t0%d\n", readByte >> 4);
            ihl = readByte & 0x0F;
            printf("Internet Header Length:\t\t\t0%x\n", readByte & 0x0F);

            // Read and print DSCP and ECN
            fread(&readByte, 1, 1, file_name);
            printf("DSCP:\t\t\t\t\t0%0x\n", readByte >> 2);
            ecn = readByte & 0x03;
            printf("ECN:\t\t\t\t\t");
            if (ecn == 0) {
                printf("Non-ECT Packet\n");
            } 
            else if (ecn == 1 || ecn == 2){
                printf("ECN-capable Packet\n"); 
            } 
            else {
                printf("Congestion Experienced\n");
            }

            // Read and print Total Length
            fread(&readByte, 1, 1, file_name);
            total_length = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            total_length |= readByte;
            printf("Total Length:\t\t\t\t%d bytes\n", total_length);

            // Read and print Identification
            fread(&readByte, 1, 1, file_name);
            identification = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            identification |= readByte;
            printf("Identification:\t\t\t\t%0x\n", identification);

            // Read and print Flags 
            fread(&readByte, 1, 1, file_name);
            printf("Flags:\t\t\t\t\t");
            flags = readByte >> 5;
            if (flags == 2) {
                printf("Don't Fragment\n");
            }
            else if (flags == 1) {
                printf("More Fragments\n");
            }
            else {
                printf("No Flag Set\n");
            }

            // Read and print Fragment Offset
            fragment_offset = ((readByte & 0x1F) << 8);
            fread(&readByte, 1, 1, file_name);
            fragment_offset |= readByte;
            printf("Fragment Offset:\t\t\t%d\n", fragment_offset);

            // Read and print Time to Live
            fread(&readByte, 1, 1, file_name);
            printf("Time to Live:\t\t\t\t%d\n", readByte);

            // Read and print Protocol
            fread(&readByte, 1, 1, file_name);
            printf("Protocol:\t\t\t\t%d\n", readByte);

            // Read and print Header Checksum
            fread(&readByte, 1, 1, file_name);
            checksum = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            checksum |= readByte;
            printf("IP Checksum:\t\t\t\t0x%04x\n", checksum);

            // Read and print Source IP Address
            printf("Source IP Address:\t\t\t");
            for (int i = 0; i < 3; i++) {
                fread(&readByte, 1, 1, file_name);
                printf("%d.", readByte);
            }
            fread(&readByte, 1, 1, file_name);
            printf("%d\n", readByte);

            // Read and print Destination IP Address
            printf("Destination IP Address:\t\t\t");
            for (int i = 0; i < 3; i++) {
                fread(&readByte, 1, 1, file_name);
                printf("%d.", readByte);
            }
            fread(&readByte, 1, 1, file_name);
            printf("%d\n", readByte);

            // Read and print Options(if any)
            option_words = ihl - 5;
            if (option_words > 0) {
                for (int i = 0; i < option_words; i++) {
                    printf("IP Option Word %d:\t\t\t0x", i + 1);
                    for (int j = 0; j < 4; j++) {
                        fread(&readByte, 1, 1, file_name);
                        printf("%02x", readByte);
                    }
                    printf("\n");
                }
                
            }
            else {
                printf("Options:\t\t\t\tNo Options\n");
            }

            // Start reading the TCP header
            printf("\nTCP Header:\n");
            printf("-----------\n");

            // Read and print Source Port
            fread(&readByte, 1, 1, file_name);
            source_port = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            source_port |= readByte;
            printf("Source Port:\t\t\t\t%d\n", source_port);

            // Read and print Destination Port
            fread(&readByte, 1, 1, file_name);
            dest_port = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            dest_port |= readByte;
            printf("Destination Port:\t\t\t%d\n", dest_port);

            // Read and print Sequence Number
            printf("Raw Sequence Number:\t\t\t");
            for (int i = 0; i < 4; i++) {
                fread(&readByte, 1, 1, file_name);
                printf("%02x", readByte);
            }
            printf("\n");

            // Read and print Acknowledgment Number
            printf("Raw Acknowledgment Number:\t\t");
            for (int i = 0; i < 4; i++) {
                fread(&readByte, 1, 1, file_name);
                printf("%02x", readByte);
            }
            printf("\n");

            // Read Data Offset and Flags
            fread(&readByte, 1, 1, file_name);
            data_offset = (readByte >> 4) & 0xF;
            printf("Data Offset:\t\t\t\t%d (32-bit words)\n", data_offset);
            fread(&readByte, 1, 1, file_name);
            flags = readByte & 0x3F;
            printf("Flags:\t\t\t\t\t");
            if (flags & 0x10) printf("ACK ");
            if (flags & 0x08) printf("PSH ");
            if (flags & 0x02) printf("SYN ");
            if (flags & 0x01) printf("FIN ");
            printf("\n");

            // Read and print Window Size
            fread(&readByte, 1, 1, file_name);
            window_size = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            window_size |= readByte;
            printf("Window Size:\t\t\t\t%d\n", window_size);

            // Read and print Checksum
            fread(&readByte, 1, 1, file_name);
            tcp_checksum = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            tcp_checksum |= readByte;
            printf("TCP Checksum:\t\t\t\t0x%04x\n", tcp_checksum);

            // Read and print Urgent Pointer
            fread(&readByte, 1, 1, file_name);
            urgent_pointer = readByte << 8;
            fread(&readByte, 1, 1, file_name);
            urgent_pointer |= readByte;
            printf("Urgent Pointer:\t\t\t\t%d\n", urgent_pointer);

            // Read and print TCP Options (if any)
            tcp_options = data_offset - 5;
            if (tcp_options > 0) {
                for (int i = 0; i < tcp_options; i++) {
                    printf("TCP Option Word %d:\t\t\t0x", i + 1);
                    for (int j = 0; j < 4; j++) {
                        fread(&readByte, 1, 1, file_name);
                        printf("%02x", readByte);
                    }
                    printf("\n");
                }
            }
            else {
                printf("Options:\t\t\t\tNo Options\n");
            }

            // Read and print Payload
            printf("\nPayload:\n");
            fread(&readByte, 1, 1, file_name);
            while (!feof(file_name)) {
                printf("%02x ", readByte);
                if ((++count % 32) == 0) {
                    printf("\n");
                }
                else if ((count % 8) == 0) {
                    printf("  ");
                }
                fread(&readByte, 1, 1, file_name);
            }
            printf("\n\n");
            fclose(file_name);
        }
    }
    return errorCode;
}
