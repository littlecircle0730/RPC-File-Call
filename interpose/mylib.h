#include <sys/types.h>
#include <dirtree.h>

#define FD_OFFSET 10000

typedef enum {
    OPEN = 0,
	CLOSE = 1,
	READ = 2,
	WRITE = 3,
	XSTAT = 4,
	LSEEK = 5,
	UNLINK = 6,
	DIRTREE = 7,
	FREE = 8,
	ENTRY = 9
} Operation;

typedef struct 
{ 
	int op;
	int header_len;
} Header;

typedef struct {
    int flags;
    mode_t mode;
    int path_len;
} OpenHeader;

typedef struct {
    int fd;
} CloseHeader;

typedef struct {
    int fd;
	int read_len;
} ReadHeader;

typedef struct {
    int read_num;
	unsigned char data[];
} ReadReceivedHeader;

typedef struct {
    int fd;
	int count;
	unsigned char data[];  // Flexible array member, C99 feature
} WriteHeader;

typedef struct
{ 
	int ver;
	int path_len;
	unsigned char data[];
} xstatHeader;

typedef struct
{ 
	int state;
	unsigned char data[];
} xstatReceivedHeader;

typedef struct
{ 
	int fd;           
	off_t offset; 
	int whence;
} LseekHeader;

typedef struct {
    int path_len;
	unsigned char data[];
} UnlinkHeader;

typedef struct
{ 
	int fd;
	size_t nbyte;
	off_t basep;
} EntryHeader;

typedef struct
{ 
	int read_num;    // how many number is read
	off_t basep;
	unsigned char data[0];  
} EntryReceivedHeader;

typedef struct
{ 
	int path_len;
	unsigned char data[];
} DirtreeHeader;

typedef struct
{ 
	int cnt_sub_dirs;
	int path_len;
	unsigned char data[];
} DirtreeReceivedHeader;


typedef struct QueueNode {
    dirtreenode* treeNode;
    struct QueueNode* next;
} QueueNode;