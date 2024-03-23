#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <dirtree.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include "mylib.h"

#define DEBUG
#define PORT_CHANGE 

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd);
ssize_t (*orig_read)(int fd,void *buf,size_t count);
ssize_t (*orig_write)(int fd, const void *buf, size_t count);
int (*orig_stat)(int ver, const char * path, struct stat * stat_buf); 
off_t(*orig_lseek)(int fd, off_t offset, int whence); 
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes , off_t *basep);
struct dirtreenode*(*orig_getdirtree)( const char *path );
void (*orig_freedirtree)( struct dirtreenode* dt );

int sockfd = 0;
char *mIp;
char *mPort;
unsigned short port;
int sockfd = 0;

/*
Serialization Functions
*/
char* serialize_open_message(const char* pathname, int flags, mode_t mode, int* outLen) {
    int path_len = strlen(pathname) + 1; // Include null terminator
    *outLen = sizeof(Header) + sizeof(OpenHeader) + path_len;
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = OPEN;
    head->header_len = *outLen;
    
    OpenHeader* openHead = (OpenHeader*)(buffer + sizeof(Header));
    openHead->flags = flags;
    openHead->mode = mode;
    openHead->path_len = path_len;
    
    // Copy pathname
    char* pathStart = buffer + sizeof(Header) + sizeof(OpenHeader);
    memcpy(pathStart, pathname, path_len);
    
    return buffer;
}

char* serialize_close_message(int fd, int* outLen) {
    *outLen = sizeof(Header) + sizeof(CloseHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = CLOSE;
    head->header_len = *outLen;
    
    CloseHeader* closeHead = (CloseHeader*)(buffer + sizeof(Header));
	closeHead->fd = fd;
    
    return buffer;
}

char* serialize_read_message(int fd ,size_t count, int* outLen) {
    *outLen = sizeof(Header) + sizeof(ReadHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = READ;
    head->header_len = *outLen;
    
    ReadHeader* readHead = (ReadHeader*)(buffer + sizeof(Header));
	readHead->fd = fd;
	readHead->read_len = count;
    
    return buffer;
}

char* serialize_write_message(int fd ,int* buf, size_t count, int* outLen) {
    *outLen = sizeof(Header) + sizeof(WriteHeader) + count;
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = WRITE;
    head->header_len = *outLen;
    
    WriteHeader* writeHead = (WriteHeader*)(buffer + sizeof(Header));
	writeHead->fd = fd;
	writeHead->count = count;
	memcpy(writeHead->data, buf, count);
    
    return buffer;
}

char* serialize_xstat_message(int ver, const char * path, struct stat * stat_buf, int* outLen) {
    *outLen = strlen(path) + 1 + sizeof(Header) + sizeof(xstatReceivedHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = XSTAT;
    head->header_len = *outLen;
    
    xstatHeader* xstatHead = (xstatHeader*)(buffer + sizeof(Header));
	xstatHead->ver = ver;
	xstatHead->path_len = strlen(path) + 1;
	memcpy(xstatHead->data, path, strlen(path) + 1);
    
    return buffer;
}

char* serialize_lseek_message(int fd, off_t offset, int whence, int* outLen) {
    *outLen = sizeof(Header) + sizeof(LseekHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = LSEEK;
    head->header_len = *outLen;
    
    LseekHeader* lseekHead = (LseekHeader*)(buffer + sizeof(Header));
	lseekHead->fd = fd;
	lseekHead->offset = offset;
	lseekHead->whence = whence;
    
    return buffer;
}

char* serialize_unlink_message(const char *pathname, int* outLen) {
	int pathLen = strlen(pathname) + 1;
    *outLen = sizeof(Header) + sizeof(UnlinkHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = UNLINK;
    head->header_len = *outLen;
    
    UnlinkHeader* unlinkHead = (UnlinkHeader*)(buffer + sizeof(Header));
	unlinkHead->path_len = pathLen;
	memcpy(unlinkHead->data, pathname, pathLen);
    
    return buffer;
}

char* serialize_getdirentries_message(int fd, char *buf, size_t nbytes , off_t *basep, int* outLen) {
    *outLen = sizeof(Header) + sizeof(EntryHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = ENTRY;
    head->header_len = *outLen;
    
    EntryHeader* entryHead = (EntryHeader*)(buffer + sizeof(Header));
    entryHead->fd = fd;
	entryHead->nbyte = nbytes;
	entryHead->basep = *(basep); // used to receive the current location in the; it's not too meaningful to get its value here 
    
    return buffer;
}

/*
Replacement Functions
*/
// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}
	
	#ifdef DEBUG
		fprintf(stderr, "mylib: open called for path %s\n", pathname);
	#endif

	// marshall
	int len;
    char* buffer = serialize_open_message(pathname, flags, m, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int msgReturn = recv(sockfd, buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	int result = atoi(buffer); // the return from server is set to a simple response?
	free(buffer);

	if (result < 0) {
		errno = -1 * result;
		return -1;
	}

	return result;
	// return orig_open(pathname, flag, mode);
}

int close(int fd) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: close called for file %d\n", fd);
	#endif

	if (fd < FD_OFFSET) {
		return orig_close(fd);
	}

	// marshall
	int len;
    char* buffer = serialize_close_message(fd, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int msgReturn = recv(sockfd, buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	int result = atoi(buffer); // the return from server is set to a simple response?
	free(buffer);

	if (result < 0) {
		errno = -1 * result;
		return -1;
	}

	return result;
	//return orig_close(fd);
}

int read(int fd,void *buf,size_t count) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: read called for file %d\n", fd);
	#endif

	// marshall
	int len;
    char* buffer = serialize_read_message(fd, count, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) { 
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int data_size_MAX = 512;
	char *complete_buffer = NULL; // Buffer to assemble the complete message
	char *recv_buffer = malloc(data_size_MAX);  // Buffer for single reception
	int msgReturn = 0;
	int total_received = 0; // Total bytes received so far
	int expected_length = -1; // Expected total length of the message, initially unknown
	int MAX_MSG = 512;
	while (1) {
        int msgReturn = recv(sockfd, recv_buffer, MAX_MSG, 0); // Here, msgReturn should be the size of received msg

		if (msgReturn < 0) {
            perror("recv failed");
            free(recv_buffer);
            free(complete_buffer);
            return -1;
        } else if (msgReturn == 0) {
            // Connection closed
            break;
        }

		if (total_received == 0) {
            // First reception, parse the expected total length of the message
			Header* header = (Header *) recv_buffer;
			expected_length = header->header_len;
			complete_buffer = malloc(expected_length);
		}

		memcpy(complete_buffer + total_received, recv_buffer, msgReturn);
		total_received += msgReturn;

		if (total_received >= expected_length) {
            // Reception complete
            break;
        }
	}
	
	free(recv_buffer); // Free the buffer for single reception
	
	if (msgReturn < 0) {
		perror("recv failed");	
		free(buffer); // Always free the allocated memory
		return -1;
	}

	// Handle returned data
	ReadReceivedHeader* readHeader = (ReadReceivedHeader*)(complete_buffer + sizeof(Header)); //TODO: check
    if (readHeader->read_num < 0) {
        errno = -1 * readHeader->read_num;
        free(complete_buffer);
        return -1;
    }

    int result = readHeader->read_num;
    // Ensure not to overflow the provided buffer
    size_t to_copy = (result < count) ? result : count;
    memcpy(buf, &readHeader->data, to_copy);

    free(complete_buffer);
    return result;
}

int write(int fd, const void *buf, size_t count) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: write called for file %d\n", fd);
	#endif

	if (fd < FD_OFFSET) {
		return orig_write(fd, buf, count);
	}

	// marshall
	int len;
    char* buffer = serialize_write_message(fd, buf, count, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int msgReturn = recv(sockfd, buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	int result = atoi(buffer); // the return from server is set to a simple response?
	free(buffer);

	if (result < 0) {
		errno = -1 * result;
		return -1;
	}

	return result;
	//return orig_write(fd, buf, count);
}


int __xstat(int ver, const char * path, struct stat * stat_buf) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: xstat called for path %d\n", path);
	#endif

	// marshall
	int len;
    char* buffer = serialize_xstate_message(ver, path, stat, stat_buf, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	void* recv_buffer = malloc(512); // set large enough space
	int msgReturn = recv(sockfd, recv_buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	xstatReceivedHeader* xstatHeader = (xstatReceivedHeader*)(recv_buffer + sizeof(Header));
    if (xstatHeader->state < 0) {
        errno = -1 * xstatHeader->state;
        free(recv_buffer);
        return -1;
    }

	int state = xstatHeader->state;
	free(buffer);
	if (state < 0) {
		free(recv_buffer);
		errno = -1*state;
		return -1;
	}
	memcpy(stat_buf, xstatHeader->data, sizeof(struct stat));
	free(recv_buffer);
	return 0;
}

off_t lseek(int fd, off_t offset, int whence) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: lseek called for file %d\n", fd);
	#endif

	if (fd < FD_OFFSET) {
		return orig_lseek(fd, offset, whence);
	}

	// marshall
	int len;
    char* buffer = serialize_lseek_message(fd, offset, whence, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int msgReturn = recv(sockfd, buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	buffer[msgReturn]=0; // set the termination for the atoi
	int result = atoi(buffer); // lseek state
	free(buffer);

	if (result < 0) {
		errno = -1 * result;
		return -1;
	}

	return result;
}

int unlink(const char *pathname) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: unlink called for path %d\n", pathname);
	#endif

	// marshall
	int len;
    char* buffer = serialize_unlink_message(pathname, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int msgReturn = recv(sockfd, buffer, len, 0);
	if (msgReturn < 0) {
		perror("recv failed");
		free(buffer); // Always free the allocated memory
		return -1;
	}

	buffer[msgReturn]=0; // set the termination for the atoi
	int result = atoi(buffer); // the return from server is set to a simple response?
	free(buffer);

	if (result < 0) {
		errno = -1 *result;
		return -1;
	}

	return result;
}

char* serialize_getdirtree_message(const char *path, int* outLen) {
	int path_length = 1 + strlen(path); // include null termination
    *outLen = path_length + sizeof(Header) + sizeof(DirtreeHeader);
    char* buffer = (char*)malloc(*outLen);
    
    Header* head = (Header*)buffer;
    head->op = DIRTREE;
    head->header_len = *outLen;
    
    DirtreeHeader* dirtreeHead = (DirtreeHeader*)(buffer + sizeof(Header));
    dirtreeHead->path_len = path_length;
	memcpy(dirtreeHead->data, path, path_length);
    
    return buffer;
}

/*
Recursively traverses and lists all contents of a specified directory and its subdirectories, providing a complete view of the directory tree.
*/
struct dirtreenode* getdirtree( const char *path ) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: dirtreenode called for path %d\n", path);
	#endif

	// marshall
	int len;
    char* buffer = serialize_getdirtree_message(path, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) {
		err(1, 0);
		free(buffer);
		return -1;
	};
	free(buffer);

	// receive
	int data_size_MAX = 512;
	char *complete_buffer = NULL; // Buffer to assemble the complete message
	char *recv_buffer = malloc(data_size_MAX);  // Buffer for single reception
	int msgReturn = 0;
	int total_received = 0; // Total bytes received so far
	int expected_length = -1; // Expected total length of the message, initially unknown
	int MAX_MSG = 512;
	while (1) {
        int msgReturn = recv(sockfd, recv_buffer, MAX_MSG, 0); // Here, msgReturn should be the size of received msg

		if (msgReturn < 0) {
            perror("recv failed");
            free(recv_buffer);
            free(complete_buffer);
            return -1;
        } else if (msgReturn == 0) {
            // Connection closed
            break;
        }

		if (total_received == 0) {
            // First reception, parse the expected total length of the message
			Header* header = (Header *) recv_buffer;
			expected_length = header->header_len;
			complete_buffer = malloc(expected_length);
		}

		memcpy(complete_buffer + total_received, recv_buffer, msgReturn);
		total_received += msgReturn;

		if (total_received >= expected_length) {
            // Reception complete
            break;
        }
	}
	
	free(recv_buffer); // Free the buffer for single reception
	
	if (msgReturn < 0) {
		perror("recv failed");	
		free(buffer); // Always free the allocated memory
		return -1;
	}

	// Handle returned data
	DirtreeReceivedHeader* entryHeader = (DirtreeReceivedHeader*)(complete_buffer + sizeof(Header));
	struct dirtreenode* headOfBuiltTree = rebuildTree((unsigned char *)entryHeader + sizeof(DirtreeReceivedHeader));
    
	free(complete_buffer);
    return headOfBuiltTree;
}

struct dirtreenode* rebuildTree(DirtreeReceivedHeader* header) {
    // Check for any error code.
    if (header->cnt_sub_dirs < 0) {
        errno = -header->cnt_sub_dirs;
        return NULL;
    }

    // Initialize the queue.
    struct dirtreenode** queue = malloc(header->cnt_sub_dirs * sizeof(struct dirtreenode*));
    int queueSize = 0;

    // Create the root node.
    char* rootName = strndup((char*)header->data, header->path_len - 1); // -1 to exclude null terminator.
    struct dirtreenode* root = new_dirtreenode(rootName, header->cnt_sub_dirs);
    queue[queueSize++] = root;

    unsigned char* buf = header->data + header->path_len; // Skip over the name of the root node.

    // BFS traversal to build the tree
    for (int i = 0; i < queueSize; i++) {
        struct dirtreenode* current = queue[i];

        // For each directory, process its subdirectories.
        for (int j = 0; j < current->num_subdirs; j++) {
            DirtreeReceivedHeader* subHeader = (DirtreeReceivedHeader*)buf;
            char* subdirName = strndup((char*)subHeader->data, subHeader->path_len - 1); // -1 to exclude null terminator.
            struct dirtreenode* subdir = new_dirtreenode(subdirName, subHeader->cnt_sub_dirs);

            // Add to the list of subdirectories of the current node.
            current->subdirs[j] = subdir;

            // If there are subdirectories, add them to the queue.
            if (subHeader->cnt_sub_dirs > 0) {
                queue[queueSize++] = subdir;
            }

            // Update the position of buf.
            buf += sizeof(DirtreeReceivedHeader) + subHeader->path_len;
        }
    }

    free(queue); // Free the memory of the queue when it's no longer needed.
    return root;
}

struct dirtreenode* new_dirtreenode(char* name, int num_subdirs) {
    struct dirtreenode* node = malloc(sizeof(struct dirtreenode));
    node->name = name;
    node->num_subdirs = num_subdirs;
    if (num_subdirs > 0) {
        node->subdirs = malloc(num_subdirs * sizeof(struct dirtreenode*));
    } else {
        node->subdirs = NULL;
    }
    return node;
}

// The freedirtree call is not a RPC call
void freedirtree( struct dirtreenode* dt ) {
	#ifdef DEBUG
		fprintf(stderr, "free tree %p \n", dt);
	#endif
	orig_freedirtree(dt);
}

/*
Lists the direct contents of a specified directory, showing files and subdirectories without entering into them.
*/
ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t *basep) {
	#ifdef DEBUG
		fprintf(stderr, "mylib: getdirentries called for file %d\n", fd);
	#endif

	if (fd < FD_OFFSET) {
		return orig_getdirentries(fd, buf, nbytes, basep);
	}

	// marshall
	int len;
    char* buffer = serialize_getdirentries_message(fd, buf, nbytes, basep, &len);

	//send message
    int check = send(sockfd, buffer, len, 0); //send and recv return -1 on error
	if (check < -1) { 
		err(1, 0);
		free(buffer);
		return -1;
	};

	// receive
	int data_size_MAX = 512;
	char *complete_buffer = NULL; // Buffer to assemble the complete message
	char *recv_buffer = malloc(data_size_MAX);  // Buffer for single reception
	int msgReturn = 0;
	int total_received = 0; // Total bytes received so far
	int expected_length = -1; // Expected total length of the message, initially unknown
	int MAX_MSG = 512;
	while (1) {
        int msgReturn = recv(sockfd, recv_buffer, MAX_MSG, 0); // Here, msgReturn should be the size of received msg

		if (msgReturn < 0) {
            perror("recv failed");
            free(recv_buffer);
            free(complete_buffer);
            return -1;
        } else if (msgReturn == 0) {
            // Connection closed
            break;
        }

		if (total_received == 0) {
            // First reception, parse the expected total length of the message
			Header* header = (Header *) recv_buffer;
			expected_length = header->header_len;
			complete_buffer = malloc(expected_length);
		}

		memcpy(complete_buffer + total_received, recv_buffer, msgReturn);
		total_received += msgReturn;

		if (total_received >= expected_length) {
            // Reception complete
            break;
        }
	}
	
	free(recv_buffer); // Free the buffer for single reception
	
	if (msgReturn < 0) {
		perror("recv failed");	
		free(buffer); // Always free the allocated memory
		return -1;
	}

	// Handle returned data
	EntryReceivedHeader* entryHeader = (EntryReceivedHeader*)(complete_buffer + sizeof(Header));
    if (entryHeader->read_num < 0) { //no data read
        errno = -1 * entryHeader->read_num;
        free(recv_buffer);
        return -1;
    }

	* basep = entryHeader->basep;
    int result = entryHeader->read_num;
    memcpy(buf, &entryHeader->data, result);

    free(complete_buffer);
    return result;
}

void _fini(void) {
	// close socket
	orig_close(sockfd);
}

// This function is automatically called when program is started
void _init(void) {
    // Set original function pointers
    orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    orig_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
    orig_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    orig_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    orig_stat = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__xstat");
    orig_lseek = (off_t (*)(int, off_t, int))dlsym(RTLD_NEXT, "lseek");
    orig_unlink = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
    orig_getdirtree = (struct dirtreenode* (*)(const char *))dlsym(RTLD_NEXT, "getdirtree");
    orig_freedirtree = (void (*)(struct dirtreenode*))dlsym(RTLD_NEXT, "freedirtree");
    orig_getdirentries = (ssize_t (*)(int, char *, size_t, off_t *))dlsym(RTLD_NEXT, "getdirentries");

    mIp = getenv("server15440") ? getenv("server15440") : "127.0.0.1";
    mPort = getenv("serverport15440") ? getenv("serverport15440") : "15440";
	#ifdef PORT_CHANGE
		mPort = "14743";
	#endif
    port = (unsigned short)atoi(mPort);

    sockfd = connect2server(mPort, port);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void _fini(void) {
    if (sockfd >= 0) {
        orig_close(sockfd);
    }
}