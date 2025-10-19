#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <limits.h>
#include <stdatomic.h>

/* Configuration constants */
#define DEFAULT_PORT 8080
#define BACKLOG_SIZE 128
#define BUFFER_SIZE 8192
#define MAX_PATH_SIZE 4096
#define MAX_LINE_SIZE 2048
#define RESPONSE_SIZE 8192
#define MAX_THREADS 100
#define MAX_HEADER_SIZE 8192

/* HTTP Status Codes */
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_METHOD_NOT_ALLOWED 405
#define HTTP_REQUEST_TOO_LARGE 413
#define HTTP_INTERNAL_ERROR 500

/* Server configuration structure */
typedef struct {
    int port;
    char* www_root;
    int server_socket;
    atomic_int shutdown_flag;
} server_config_t;

/* HTTP request structure */
typedef struct {
    char method[16];
    char path[MAX_PATH_SIZE];
    char version[16];
} http_request_t;

/* Client information structure */
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
    server_config_t* config;
} client_info_t;

/* Function declarations */
void log_message(const char* level, const char* format, ...);
int create_server_socket(int port);
void setup_signal_handlers(void);
void signal_handler(int sig);
void* handle_client(void* arg);
int parse_http_request(const char* raw_request, http_request_t* request);
void send_error_response(int client_socket, int status_code);
void send_http_response(int client_socket, int status_code, const char* content_type,
    const char* body, size_t body_length);
char* sanitize_path(const char* path);
int is_safe_path(const char* request_path, const char* www_root);
void serve_file(int client_socket, const char* filepath);
char* get_mime_type(const char* filename);
void cleanup_resources(void);
int is_symlink(const char* path);

/* Global server configuration */
extern server_config_t g_server_config;

#endif /* WEBSERVER_H */
