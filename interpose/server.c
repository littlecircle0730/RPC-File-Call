#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "../include/dirtree.h"
#include "mylib.h"

#define MAXMSGLEN 250

typedef struct dirtreenode dirtreenode;

int main(int argc, char**argv) {
	char *msg="Hello from server";
	char buf[MAXMSGLEN+1];
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv, i;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	int connection = 0;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=15440;
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);
	
	// main server loop
	while (1) {
		// wait for next client, get session socket
		sa_size = sizeof(struct sockaddr_in);
		connection = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (connection<0) err(1,0);
		// handle multiple concurrent clients
		if (fork() == 0) {
			close(sockfd);
			serve_client(connection);
			close(connection);
			exit(0);
		}
		// parent close connection
		close(connection);
	}

	printf("server shutting down cleanly\n");
	// close socket
	close(sockfd);

	return 0;
}

void serve_client(int connection) {
    char buf[MAXMSGLEN];
    int sessfd = connection;
    ssize_t rv;

    while (1) {
        // Buffer to store received data
        char* buffer = NULL;
        int total_received = 0; // Total bytes received for current request
        int expected_length = -1; // Expected length of the complete request

        // Receive data in a loop until we have the complete message
        while ((rv = recv(sessfd, buf, MAXMSGLEN, 0)) > 0) {
            if (total_received == 0) {
                // First chunk of data, extract the expected total length of the request
                Header* header = (Header*)buf;
                expected_length = header->header_len;

                // Allocate buffer to store the complete request
                buffer = (char*)malloc(expected_length);
                if (!buffer) {
                    perror("Failed to allocate buffer");
                    break;
                }
            }

            // Check if the buffer is allocated
            if (buffer) {
                // Append received data to the buffer
                memcpy(buffer + total_received, buf, rv);
                total_received += rv;

                // Check if we have received the complete request
                if (total_received >= expected_length) {
                    break; // Exit the loop if the complete request is received
                }
            }
        }

        // Check for receive errors
        if (rv < 0) {
            perror("recv failed");
            free(buffer);
            break; // Exit the loop on error
        }

        // Handle the received RPC request
        if (buffer) {
            handleRPC(buffer, sessfd);
            free(buffer); // Always free the allocated buffer
        } else {
            // If buffer allocation failed, exit the loop
            break;
        }
    }

    // Close the connection when done
    close(sessfd);
}

void handleRPC(void* buffer, int sessfd) {
    Header* header = (Header*) buffer;
    int opcode = header->op;

    #ifdef DEBUG
    fprintf(stderr, "Received OPCODE: %d \n", opcode);
    #endif

    void* operationData = buffer + sizeof(Header);

    switch (opcode) {
        case OPEN: {
            OpenHeader* openData = (OpenHeader*)operationData;
            process_open(openData, sessfd);
            break;
        }
        case CLOSE: {
            CloseHeader* closeData = (CloseHeader*)operationData;
            process_close(closeData, sessfd);
            break;
        }
        case READ: {
            ReadHeader* readData = (ReadHeader*)operationData;
            process_read(readData, sessfd);
            break;
        }
        case WRITE: {
            WriteHeader* writeData = (WriteHeader*)operationData;
            process_write(writeData, sessfd);
            break;
        }
        case XSTAT: {
            xstatHeader* xstatData = (xstatHeader*)operationData;
            process_xstat(xstatData, sessfd);
            break;
        }
        case LSEEK: {
            LseekHeader* lseekData = (LseekHeader*)operationData;
            process_lseek(lseekData, sessfd);
            break;
        }
        case UNLINK: {
            UnlinkHeader* unlinkData = (UnlinkHeader*)operationData;
            process_unlink(unlinkData, sessfd);
            break;
        }
        case ENTRY: {
            EntryHeader* entryData = (EntryHeader*)operationData;
            process_getEntry(entryData, sessfd);
            break;
        }
		case DIRTREE: {
            char* filepath = (char*)buffer + sizeof(Header);
            DirtreeHeader * treeData = (DirtreeHeader *)operationData;
			process_dirtree(treeData, sessfd);
			break;
		}
        default:
            fprintf(stderr, "Unsupported opcode: %d\n", opcode);
    }
}

void process_open(void* buffer, int sessfd) {
    OpenHeader* open_header = (OpenHeader*) buffer;
    // Assuming the file path immediately follows the OpenHeader structure in memory
    char* filepath = (char*)(open_header + 1); // Pointer arithmetic to access data following OpenHeader

    int fd = open(filepath, open_header->flags, open_header->mode);
    if (fd < 0) {
        fd = -errno;
    } else {
        fd += FD_OFFSET;
    }

    char response[20];
    snprintf(response, sizeof(response), "%d", fd);
    send(sessfd, response, strlen(response) + 1, 0);
}

void process_close(CloseHeader *close_header, int sessfd) {
    int fd = close_header->fd - FD_OFFSET; // Adjust with FD_OFFSET
    int result = close(fd); // Attempt file close operation
    if (result < 0) {
        result = -errno; // Convert errno to a negative value on error
    }

    // Send the result back to the client
    char response[20];
    snprintf(response, sizeof(response), "%d", result);
    send(sessfd, response, strlen(response) + 1, 0); // +1 for null terminator
}

void process_read(ReadHeader *read_header, int sessfd) {
    // Allocate buffer for reading data
    char *buf = malloc(read_header->read_len);

    // Adjust file descriptor with FD_OFFSET
    int fd = read_header->fd - FD_OFFSET;

    // Perform read operation
    ssize_t bytesRead = read(fd, buf, read_header->read_len);
    
    // Prepare the response
    char *response;
    int responseLength;

    if (bytesRead < 0) {
        // In case of read error, prepare error response
        bytesRead = -errno; // Use negative errno as error indication
        responseLength = sizeof(Header) + sizeof(ReadReceivedHeader);
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = READ;
        header->header_len = responseLength;
        ReadReceivedHeader* reply_header = (ReadReceivedHeader *)(response + sizeof(Header));
        reply_header->read_num = bytesRead; // Indicate error with negative value
    } else {
        // In case of successful read, include the data in the response
        responseLength = sizeof(Header) + sizeof(ReadReceivedHeader) + bytesRead;
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = READ;
        header->header_len = responseLength;
        ReadReceivedHeader* reply_header = (ReadReceivedHeader *)(response + sizeof(Header));
        reply_header->read_num = bytesRead; // Indicate successful read with positive bytes read
        memcpy(reply_header + 1, buf, bytesRead); // Copy read data right after the ReadReceivedHeader
    }

    // Send the response back to the client
    send(sessfd, response, responseLength, 0);

    // Clean up
    free(buf);
    free(response);
}

void process_write(WriteHeader *write_header, int sessfd) {
    int fd = write_header->fd - FD_OFFSET; // Adjust with FD_OFFSET

    ssize_t bytesWritten = write(fd, write_header->data, write_header->count); // Perform write
    if (bytesWritten < 0) {
        bytesWritten = -errno; // Convert errno to negative on error
    }

    // Prepare and send write result
    char response[20];
    snprintf(response, sizeof(response), "%ld", bytesWritten); // Use %ld for ssize_t
    send(sessfd, response, strlen(response) + 1, 0); // +1 for null terminator
}

void process_stat(xstatHeader *stat_header, int sessfd) {
    // Extract the file path from the request
    char *path = malloc(stat_header->path_len + 1); // +1 for null terminator
    memcpy(path, stat_header->data, stat_header->path_len);
    path[stat_header->path_len] = '\0'; // Ensure null termination

    struct stat statbuf;
    int result = __xstat(stat_header->ver, path, &statbuf);
    
    // Prepare the response
    char *response;
    int responseLength;

    if (result < 0) {
        // In case of error, prepare an error response
        result = -errno; // Use negative errno as error indication
        responseLength = sizeof(Header) + sizeof(xstatReceivedHeader);
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = XSTAT;
        header->header_len = responseLength;
        xstatReceivedHeader* reply_header = (xstatReceivedHeader *)(response + sizeof(Header));
        reply_header->state = result; // Indicate error with negative value
        // Assuming that xstatReceivedHeader has a field to indicate error condition
    } else {
        // In case of successful stat, include the stat data in the response
        // Assuming we serialize struct stat to a buffer or have a predefined format in xstatReceivedHeader
        // Here we should properly serialize struct stat into a suitable format
        // For simplicity, let's assume xstatReceivedHeader can directly hold the stat data
        responseLength = sizeof(Header) + sizeof(xstatReceivedHeader) + sizeof(struct stat);
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = XSTAT;
        header->header_len = responseLength;
        xstatReceivedHeader* reply_header = (xstatReceivedHeader *)(response + sizeof(Header));
        reply_header->state = result; // Indicate success
        // Properly serialize or copy stat struct into the response
        memcpy(reply_header->data, &statbuf, sizeof(struct stat));
    }

    // Send the response back to the client
    send(sessfd, response, responseLength, 0);

    free(path); // Clean up
    free(response);
}

void process_lseek(LseekHeader *lseek_header, int sessfd) {
    // Extract parameters from the header
    int fd = lseek_header->fd - FD_OFFSET; // Adjust fd for server-side usage
    off_t offset = lseek_header->offset;
    int whence = lseek_header->whence;

    // Attempt to change the file offset
    off_t newPosition = lseek(fd, offset, whence);

    // Check the result of the lseek operation
    if (newPosition < 0) {
        // Operation failed, prepare an error message
        newPosition = -errno; // Use negative errno value to indicate failure
    } 

    // Create a simple message containing the result (or error)
    char resultMessage[64]; // Ensure this buffer is large enough
    int messageLength = snprintf(resultMessage, sizeof(resultMessage), "%ld", newPosition);

    // Send the result back to the client
    if (send(sessfd, resultMessage, messageLength + 1, 0) < 0) { // +1 to include null terminator
        perror("Error sending lseek result to client");
    }
}

void process_unlink(UnlinkHeader *unlink_header, int sessfd) {
    // Extract the pathname
    int pathLen = unlink_header->path_len;
    char* pathname = strndup((char*)unlink_header->data, pathLen);

    // Attempt the unlink operation
    int unlink_result = unlink(pathname);
    if (unlink_result < 0) {
        unlink_result = -errno; // Use negative errno value to indicate an error
    }

    // Prepare the response message
    char response[20]; // Ensure this buffer is large enough
    snprintf(response, sizeof(response), "%d", unlink_result);

    // Send the result of the unlink operation back to the client
    if (send(sessfd, response, strlen(response) + 1, 0) < 0) { // +1 to include the null terminator
        perror("Error sending unlink result to client");
    }

    // Free the memory allocated for pathname
    free(pathname);
}

void process_getEntry(EntryHeader * entryHeader, int sessfd) {
    int fd = entryHeader->fd - FD_OFFSET;
    size_t nbytes = entryHeader->nbyte;
    off_t basep = entryHeader->basep;
    char* buf = malloc(nbytes);

    #ifdef DEBUG
        fprintf(stderr, "Server getentry going to call data! %d %p %ld\n", fd, buf, basep);
    #endif

	// &basep pass the address
    int read_num = getdirentries(fd, buf, nbytes, &basep);

    #ifdef DEBUG
        fprintf(stderr, "Server getentry to send read number! %d \n", read_num);
    #endif

    char *buffer = NULL;
    int length = 0;

    if (read_num < 0) {
        read_num = -1 * errno;
        length = sizeof(Header) + sizeof(EntryHeader);
        buffer = malloc(length);
        Header *header = (Header *)buffer;
        header->op = ENTRY;
        header->header_len = length;
        EntryReceivedHeader* receive_header = (EntryReceivedHeader *)(buffer + sizeof(Header));
        receive_header->read_num = read_num;
    } else {
        // read success and prepare to return data
        length = sizeof(Header) + sizeof(EntryReceivedHeader) + read_num;
        buffer = malloc(length);
        Header *header = (Header *)buffer;
        header->op = ENTRY;
        header->header_len = length;
        EntryReceivedHeader* receive_header = (EntryReceivedHeader *)(buffer + sizeof(Header));
        receive_header->read_num = read_num;
        receive_header->basep = basep; // update basep
        memcpy(receive_header->data, buf, read_num);       
    }

    free(buf);
    int k = send(sessfd, buffer, length, 0); 
    if (k < 0) {
        perror("send failed");
    }
    
    free(buffer);
}

void process_dirtree(void* buffer, int sessfd) {
    // Extract the file path from the buffer
    DirtreeHeader* dirtree_header = (DirtreeHeader*) buffer;
    char* filename = malloc(dirtree_header->path_len + 1); // +1 for null terminator
    memcpy(filename, dirtree_header->data, dirtree_header->path_len);
    filename[dirtree_header->path_len] = '\0'; // Ensure null termination

    // Attempt to get the directory tree
    dirtreenode* dirHead = getdirtree(filename);
    free(filename); // Filename is no longer needed after this point

    // Initialize variables for sending response
    char *response;
    int responseLength;

    if (dirHead == NULL) {
        // On error, prepare an error response
        int error = -errno;
        responseLength = sizeof(Header) + sizeof(DirtreeReceivedHeader);
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = DIRTREE;
        header->header_len = responseLength;
        DirtreeReceivedHeader* reply_header = (DirtreeReceivedHeader*)(response + sizeof(Header));
        reply_header->cnt_sub_dirs = error; // Use negative error code
    } else {
        // On success, serialize the directory tree into a response
        int totalLen = get_total_len(dirHead);
        responseLength = sizeof(Header) + totalLen; // Assuming totalLen accounts for the size of DirtreeReceivedHeader
        response = malloc(responseLength);
        Header *header = (Header *)response;
        header->op = DIRTREE;
        header->header_len = responseLength;
        encodeTree(dirHead, response + sizeof(Header));
        freedirtree(dirHead); // Clean up the directory tree
    }

    // Send the response back to the client
    int sentResult = -1;
    while (sentResult<0) {
        // try resend if fails i.e sentResult<0
        send(sessfd, response, responseLength, 0); 
    }
    free(response); // Free the response buffer after sending
}

int get_total_len(dirtreenode* dirHead) {
    if (dirHead == NULL) return sizeof(DirtreeReceivedHeader); // Base size for an empty node
    
    int total_len = sizeof(DirtreeReceivedHeader) + strlen(dirHead->name) + 1; // Include name length and null terminator
    for (int i = 0; i < dirHead->num_subdirs; i++) {
        total_len += get_total_len(dirHead->subdirs[i]); // Recursively add the length of subdirectories
    }
    return total_len;
}

void encodeTree(dirtreenode* dirHead, unsigned char** bufPtr) {
    if (dirHead == NULL) return;

    // Initialize the queue for breadth-first traversal
    QueueNode* queueHead = NULL, *queueTail = NULL;
    enqueue(&queueHead, &queueTail, dirHead);

    while (queueHead != NULL) {
        dirtreenode* currentNode = dequeue(&queueHead);

        // Calculate the length of the current node's name including the null terminator
        int nameLen = strlen(currentNode->name) + 1;

        // Prepare the node header information
        DirtreeReceivedHeader* header = (DirtreeReceivedHeader*)(*bufPtr);
        header->cnt_sub_dirs = currentNode->num_subdirs;
        header->path_len = nameLen;

        // Copy the node's name to the position pointed to by bufPtr
        memcpy(header->data, currentNode->name, nameLen);

        // Update bufPtr to point to the start position of the next node
        *bufPtr += sizeof(DirtreeReceivedHeader) + nameLen - 1; // -1 because data[] already counts one byte

        // Add all subnodes to the queue
        for (int i = 0; i < currentNode->num_subdirs; i++) {
            enqueue(&queueHead, &queueTail, currentNode->subdirs[i]);
        }
    }
}

void enqueue(QueueNode** head, QueueNode** tail, dirtreenode* node) {
    QueueNode* newNode = (QueueNode*)malloc(sizeof(QueueNode));
    newNode->treeNode = node;
    newNode->next = NULL;
    if (*tail != NULL) {
        (*tail)->next = newNode;
    }
    *tail = newNode;
    if (*head == NULL) {
        *head = newNode;
    }
}

dirtreenode* dequeue(QueueNode** head) {
    if (*head == NULL) return NULL;
    QueueNode* temp = *head;
    dirtreenode* result = temp->treeNode;
    *head = (*head)->next;
    free(temp);
    return result;
}