typedef unsigned char uint8_t;
typedef signed char int8_t;

typedef unsigned short uint16_t;
typedef signed short int16_t;

typedef unsigned int uint32_t;
typedef signed int int32_t;

typedef unsigned long long uint64_t;
typedef signed long long int64_t;

enum ram_command {
    CMD_RAM_COMPANY_INFO    = 0x0,
    CMD_RAM_ALLOC           = 0x1,
    CMD_RAM_FREE            = 0x2,
    CMD_RAM_READ            = 0x3,
    CMD_RAM_WRITE           = 0x4,
    CMD_RAM_CLEAR           = 0x5,
    CMD_RAM_AVAILABLE       = 0x6,
    CMD_RAM_DEFRAGMENT      = 0x7,
};

enum ram_error {
    ERR_NO_ERROR            = 0x0,
    ERR_INVALID_CMD         = 0xC0000001,
    ERR_INVALID_SIZE        = 0xC0000002,
    ERR_NO_SPACE_LEFT       = 0xC0000003,
    ERR_ENTRY_NOT_FOUND     = 0xC0000004,
    ERR_INVALID_PACKET      = 0xC0000005,
    ERR_MAX_ID              = 0xC0000006,
    ERR_CHECKSUM            = 0xC0000007,
    ERR_INVALID_ENC_SIZE    = 0xC0000008,
};

struct packet_create_t {
    uint16_t size;
    uint8_t enc_status;
};

struct packet_store_t {
    uint32_t id;
    uint16_t size;
};

struct ram_cell_info_t {
    uint16_t checksum;
    uint16_t size;
    uint16_t size_enc;
    uint16_t pad0;
    uint32_t id;
};

struct ram_cell_t {
    struct ram_cell_info_t;
    char buf[];
};

struct ram_cell_header_t {
    uint8_t enc_status;
    uint16_t size;
};

struct ram_entry_t {
    struct ram_cell_header_t header;
    struct ram_cell_t *cell;
    struct ram_entry_t *next;
    struct ram_entry_t *prev;
};

struct ram_list_entry {
    struct ram_entry_t *next;
    struct ram_entry_t *prev;
};

struct cell_list_entry {
    struct ram_entry_t *start;
    struct ram_list_entry *head;
};