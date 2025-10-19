#include "Webserver.h"

#define MIME_TYPES_COUNT (sizeof(mime_types) / sizeof(mime_types[0]))

/* Global server configuration */
server_config_t g_server_config = { 0 };

/* Thread pool management */
static atomic_int active_threads = 0;
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    const char* extension;
    const char* mime_type;
} mime_mapping_t;

static const mime_mapping_t mime_types[] = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".xml", "application/xml"},
    {".txt", "text/plain"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".ico", "image/x-icon"},
    {".svg", "image/svg+xml"},
    {NULL, "application/octet-stream"} // Default
};

/* log_message logs message with timestamp */
void log_message(const char* level, const char* format, ...)
{
    va_list args;
    time_t now;
    struct tm* timeinfo;
    char timestamp[64];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("[%s] [%s] ", timestamp, level);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);
}

/* create_server_socket creates and configures server socket */
int create_server_socket(int port)
{
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;

    // create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        log_message("ERROR", "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // set socket options for address reuse
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message("ERROR", "Failed to set socket options: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    // configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message("ERROR", "Failed to bind socket: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    // listen for connections
    if (listen(server_socket, BACKLOG_SIZE) < 0) {
        log_message("ERROR", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    return server_socket;
}

/* setup_signal_handlers set handlers for graceful shutdown */
void setup_signal_handlers(void)
{
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log_message("ERROR", "Failed to set SIGINT handler: %s", strerror(errno));
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        log_message("ERROR", "Failed to set SIGTERM handler: %s", strerror(errno));
    }

    // Ignore SIGPIPE - handle send() errors instead
    signal(SIGPIPE, SIG_IGN);
}

/* signal_handler for graceful shutdown */
void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        log_message("INFO", "Received signal %d, shutting down gracefully", sig);
        atomic_store(&g_server_config.shutdown_flag, 1);
        break;
    }
}

/* is_symlink checks if path is a symbolic link */
int is_symlink(const char* path)
{
    struct stat path_stat;
    if (lstat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISLNK(path_stat.st_mode);
}

/* handle_client handles client connection in separate thread */
void* handle_client(void* arg)
{
    client_info_t* client_info = (client_info_t*)arg;
    int client_socket = client_info->client_socket;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    http_request_t request;

    log_message("DEBUG", "Handling client %s", inet_ntoa(client_info->client_addr.sin_addr));

    // set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message("WARN", "Failed to set receive timeout: %s", strerror(errno));
    }
    if (setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_message("WARN", "Failed to set send timeout: %s", strerror(errno));
    }

    // Read HTTP request
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received < 0) {
        log_message("WARN", "Failed to receive data from client: %s", strerror(errno));
        goto cleanup;
    }

    if (bytes_received == 0) {
        log_message("DEBUG", "Client closed connection");
        goto cleanup;
    }

    // Check for oversized request
    if (bytes_received >= MAX_HEADER_SIZE) {
        log_message("WARN", "Request too large: %zd bytes", bytes_received);
        send_error_response(client_socket, HTTP_REQUEST_TOO_LARGE);
        goto cleanup;
    }

    buffer[bytes_received] = '\0';
    log_message("DEBUG", "Received request: %.*s", 100, buffer);

    // parse HTTP request
    if (parse_http_request(buffer, &request) != 0) {
        log_message("WARN", "Failed to parse HTTP request");
        send_error_response(client_socket, HTTP_BAD_REQUEST);
        goto cleanup;
    }

    // only support GET method
    if (strcmp(request.method, "GET") != 0) {
        log_message("WARN", "Unsupported method: %s", request.method);
        send_error_response(client_socket, HTTP_METHOD_NOT_ALLOWED);
        goto cleanup;
    }

    // sanitize and validate path
    char* safe_path = sanitize_path(request.path);
    if (!safe_path) {
        log_message("WARN", "Path sanitization failed");
        send_error_response(client_socket, HTTP_BAD_REQUEST);
        goto cleanup;
    }

    if (!is_safe_path(safe_path, client_info->config->www_root)) {
        log_message("WARN", "Directory traversal attempt detected: %s", safe_path);
        free(safe_path);
        send_error_response(client_socket, HTTP_FORBIDDEN);
        goto cleanup;
    }

    // construct full file path
    char full_path[MAX_PATH_SIZE];
    int path_len = snprintf(full_path, sizeof(full_path), "%s%s",
        client_info->config->www_root, safe_path);

    if (path_len >= (int)sizeof(full_path)) {
        log_message("WARN", "Path too long after construction");
        free(safe_path);
        send_error_response(client_socket, HTTP_BAD_REQUEST);
        goto cleanup;
    }

    // Check for symbolic links
    if (is_symlink(full_path)) {
        log_message("WARN", "Symbolic link detected and rejected: %s", full_path);
        free(safe_path);
        send_error_response(client_socket, HTTP_FORBIDDEN);
        goto cleanup;
    }

    // check if path is a directory and serve index.html
    struct stat path_stat;
    if (stat(full_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
        char index_path[MAX_PATH_SIZE];
        int idx_len = snprintf(index_path, sizeof(index_path), "%s/index.html", full_path);

        if (idx_len >= (int)sizeof(index_path)) {
            log_message("WARN", "Index path too long");
            free(safe_path);
            send_error_response(client_socket, HTTP_BAD_REQUEST);
            goto cleanup;
        }

        if (access(index_path, R_OK) == 0) {
            strncpy(full_path, index_path, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
        }
        else {
            free(safe_path);
            send_error_response(client_socket, HTTP_NOT_FOUND);
            goto cleanup;
        }
    }

    // serve file
    serve_file(client_socket, full_path);
    free(safe_path);

cleanup:
    close(client_socket);
    free(client_info);

    // decrement active thread count
    atomic_fetch_sub(&active_threads, 1);

    return NULL;
}

/* parse_http_request parses http request into components */
int parse_http_request(const char* raw_request, http_request_t* request)
{
    if (!raw_request || !request) {
        return -1;
    }

    // clear the request structure
    memset(request, 0, sizeof(http_request_t));

    // find the end of the first line
    const char* end_of_line = strstr(raw_request, "\r\n");
    if (!end_of_line) {
        end_of_line = strchr(raw_request, '\n');
        if (!end_of_line) {
            return -1;
        }
    }

    // parse the request line: METHOD PATH VERSION
    char request_line[MAX_LINE_SIZE];
    size_t line_length = end_of_line - raw_request;
    if (line_length >= sizeof(request_line)) {
        return -1;
    }

    strncpy(request_line, raw_request, line_length);
    request_line[line_length] = '\0';

    // extract method, path, version
    char* saveptr = NULL;
    char* token = strtok_r(request_line, " ", &saveptr);
    if (!token) {
        return -1;
    }
    strncpy(request->method, token, sizeof(request->method) - 1);
    request->method[sizeof(request->method) - 1] = '\0';

    token = strtok_r(NULL, " ", &saveptr);
    if (!token) {
        return -1;
    }
    strncpy(request->path, token, sizeof(request->path) - 1);
    request->path[sizeof(request->path) - 1] = '\0';

    token = strtok_r(NULL, " ", &saveptr);
    if (!token) {
        return -1;
    }
    strncpy(request->version, token, sizeof(request->version) - 1);
    request->version[sizeof(request->version) - 1] = '\0';

    return 0;
}

/* send_error_response sends HTTP error response */
void send_error_response(int client_socket, int status_code)
{
    const char* status_text;
    const char* body;

    switch (status_code) {
    case HTTP_BAD_REQUEST:
        status_text = "Bad Request";
        body = "<html><body><h1>400 Bad Request</h1></body></html>";
        break;
    case HTTP_FORBIDDEN:
        status_text = "Forbidden";
        body = "<html><body><h1>403 Forbidden</h1></body></html>";
        break;
    case HTTP_NOT_FOUND:
        status_text = "Not Found";
        body = "<html><body><h1>404 Not Found</h1></body></html>";
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        status_text = "Method Not Allowed";
        body = "<html><body><h1>405 Method Not Allowed</h1></body></html>";
        break;
    case HTTP_REQUEST_TOO_LARGE:
        status_text = "Request Entity Too Large";
        body = "<html><body><h1>413 Request Too Large</h1></body></html>";
        break;
    case HTTP_INTERNAL_ERROR:
        status_text = "Internal Server Error";
        body = "<html><body><h1>500 Internal Server Error</h1></body></html>";
        break;
    default:
        status_text = "Unknown Error";
        body = "<html><body><h1>Unknown Error</h1></body></html>";
    }

    send_http_response(client_socket, status_code, "text/html", body, strlen(body));
}

/* send_http_response sends HTTP response with headers and body */
void send_http_response(int client_socket, int status_code, const char* content_type,
    const char* body, size_t body_length)
{
    char response[RESPONSE_SIZE];
    const char* status_text;

    // Map status code to text
    switch (status_code) {
    case HTTP_OK:
        status_text = "OK";
        break;
    case HTTP_BAD_REQUEST:
        status_text = "Bad Request";
        break;
    case HTTP_FORBIDDEN:
        status_text = "Forbidden";
        break;
    case HTTP_NOT_FOUND:
        status_text = "Not Found";
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        status_text = "Method Not Allowed";
        break;
    case HTTP_REQUEST_TOO_LARGE:
        status_text = "Request Entity Too Large";
        break;
    case HTTP_INTERNAL_ERROR:
        status_text = "Internal Server Error";
        break;
    default:
        status_text = "Unknown";
    }

    int header_len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Server: CustomWebServer/1.0\r\n"
        "\r\n",
        status_code,
        status_text,
        content_type,
        body_length);

    if (header_len >= (int)sizeof(response)) {
        log_message("ERROR", "Response header truncated");
        return;
    }

    // Send headers
    ssize_t sent = send(client_socket, response, header_len, 0);
    if (sent < 0) {
        log_message("ERROR", "Failed to send response headers: %s", strerror(errno));
        return;
    }
    if (sent < header_len) {
        log_message("WARN", "Partial header send: %zd of %d bytes", sent, header_len);
    }

    // Send body if present
    if (body && body_length > 0) {
        sent = send(client_socket, body, body_length, 0);
        if (sent < 0) {
            log_message("ERROR", "Failed to send response body: %s", strerror(errno));
            return;
        }
        if (sent < (ssize_t)body_length) {
            log_message("WARN", "Partial body send: %zd of %zu bytes", sent, body_length);
        }
    }
}

/* sanitize_path sanitizes file path to prevent directory traversal */
char* sanitize_path(const char* path)
{
    if (!path) {
        return NULL;
    }

    size_t len = strlen(path);
    if (len > MAX_PATH_SIZE - 2) {
        return NULL;
    }

    char* sanitized = malloc(len + 2); // extra space for potential '/' and null terminator
    if (!sanitized) {
        return NULL;
    }

    strcpy(sanitized, path);

    // ensure path starts with '/'
    if (sanitized[0] != '/') {
        memmove(sanitized + 1, sanitized, len + 1);
        sanitized[0] = '/';
        len++;
    }

    // url decode
    char* src = sanitized;
    char* dst = sanitized;
    while (*src) {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], 0 };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        }
        else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    // remove consecutive slashes
    src = dst = sanitized;
    while (*src) {
        *dst++ = *src;
        if (*src == '/') {
            while (*++src == '/');
        }
        else {
            src++;
        }
    }
    *dst = '\0';

    // remove . and .. components
    char* components[256];
    int component_count = 0;

    char* path_copy = strdup(sanitized);
    if (!path_copy) {
        free(sanitized);
        return NULL;
    }

    char* saveptr = NULL;
    char* token = strtok_r(path_copy, "/", &saveptr);
    while (token && component_count < 256) {
        if (strcmp(token, ".") == 0) {
            // skip current directory reference
        }
        else if (strcmp(token, "..") == 0) {
            // go back one directory
            if (component_count > 0) {
                component_count--;
            }
        }
        else {
            components[component_count++] = token;
        }
        token = strtok_r(NULL, "/", &saveptr);
    }

    // rebuild the path
    strcpy(sanitized, "/");
    for (int i = 0; i < component_count; ++i) {
        if (i > 0) {
            strcat(sanitized, "/");
        }
        strcat(sanitized, components[i]);
    }

    free(path_copy);
    return sanitized;
}

/* is_safe_path checks if path is safe within www_root */
int is_safe_path(const char* request_path, const char* www_root)
{
    if (!request_path || !www_root) {
        return 0;
    }

    char full_path[PATH_MAX];
    char canonical_path[PATH_MAX];
    char canonical_root[PATH_MAX];

    // construct full path
    int path_len = snprintf(full_path, sizeof(full_path), "%s%s", www_root, request_path);
    if (path_len >= (int)sizeof(full_path)) {
        log_message("WARN", "Path construction overflow");
        return 0;
    }

    // get canonical paths
    if (!realpath(www_root, canonical_root)) {
        log_message("WARN", "Failed to resolve www_root: %s", strerror(errno));
        return 0;
    }

    // for non-existent files, check the directory portion
    char* last_slash = strrchr(full_path, '/');
    if (last_slash && last_slash != full_path) {
        *last_slash = '\0';
        if (!realpath(full_path, canonical_path)) {
            // Directory doesn't exist
            return 0;
        }
        *last_slash = '/';

        // Check if we have space to concatenate
        size_t canonical_len = strlen(canonical_path);
        size_t slash_part_len = strlen(last_slash);
        if (canonical_len + slash_part_len >= PATH_MAX) {
            log_message("WARN", "Canonical path would overflow");
            return 0;
        }
        strcat(canonical_path, last_slash);
    }
    else {
        if (!realpath(full_path, canonical_path)) {
            // File doesn't exist, but we still need to check the path
            // Try to get the directory part
            char dir_path[PATH_MAX];
            strncpy(dir_path, full_path, sizeof(dir_path) - 1);
            dir_path[sizeof(dir_path) - 1] = '\0';

            char* last_dir_slash = strrchr(dir_path, '/');
            if (last_dir_slash) {
                *last_dir_slash = '\0';
                if (!realpath(dir_path, canonical_path)) {
                    return 0;
                }
            }
            else {
                return 0;
            }
        }
    }

    // check if canonical path starts with canonical root
    size_t root_len = strlen(canonical_root);
    size_t path_check_len = strlen(canonical_path);

    // Bounds check before accessing array
    if (path_check_len < root_len) {
        return 0;
    }

    return strncmp(canonical_path, canonical_root, root_len) == 0 &&
        (canonical_path[root_len] == '/' || canonical_path[root_len] == '\0');
}

/* serve_file serves file to client */
void serve_file(int client_socket, const char* filepath)
{
    struct stat file_stat;

    // check if file exists and is readable
    if (stat(filepath, &file_stat) != 0) {
        log_message("WARN", "File not found: %s", filepath);
        send_error_response(client_socket, HTTP_NOT_FOUND);
        return;
    }

    if (!S_ISREG(file_stat.st_mode)) {
        log_message("WARN", "Not a regular file: %s", filepath);
        send_error_response(client_socket, HTTP_FORBIDDEN);
        return;
    }

    int file_fd = open(filepath, O_RDONLY);
    if (file_fd < 0) {
        log_message("ERROR", "Failed to open file: %s - %s", filepath, strerror(errno));
        send_error_response(client_socket, HTTP_INTERNAL_ERROR);
        return;
    }

    // get MIME type
    char* content_type = get_mime_type(filepath);

    // send HTTP response headers
    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "Server: CustomWebServer/1.0\r\n"
        "\r\n",
        content_type, file_stat.st_size);

    if (header_len >= (int)sizeof(header)) {
        log_message("ERROR", "Response header truncated");
        close(file_fd);
        send_error_response(client_socket, HTTP_INTERNAL_ERROR);
        return;
    }

    ssize_t sent = send(client_socket, header, header_len, 0);
    if (sent < 0) {
        log_message("ERROR", "Failed to send headers: %s", strerror(errno));
        close(file_fd);
        return;
    }
    if (sent < header_len) {
        log_message("WARN", "Partial header send: %zd of %d bytes", sent, header_len);
    }

    // send file content using sendfile for efficiency
    off_t offset = 0;
    ssize_t total_sent = 0;
    ssize_t remaining = file_stat.st_size;

    while (remaining > 0) {
        sent = sendfile(client_socket, file_fd, &offset, remaining);
        if (sent <= 0) {
            if (sent < 0) {
                log_message("ERROR", "Failed to send file content: %s", strerror(errno));
            }
            break;
        }
        total_sent += sent;
        remaining -= sent;
    }

    if (total_sent == file_stat.st_size) {
        log_message("INFO", "Served file: %s (%ld bytes)", filepath, total_sent);
    }
    else {
        log_message("WARN", "Partial file send: %zd of %ld bytes", total_sent, file_stat.st_size);
    }

    close(file_fd);
}

/* get_mime_type returns MIME type based on file extension */
char* get_mime_type(const char* filename)
{
    if (!filename) {
        return "application/octet-stream";
    }

    const char* ext = strrchr(filename, '.');
    if (!ext) {
        return "application/octet-stream";
    }

    // convert extension to lowercase
    char lower_ext[16];
    int i;
    for (i = 0; i < (int)sizeof(lower_ext) - 1 && ext[i]; ++i) {
        lower_ext[i] = tolower((unsigned char)ext[i]);
    }
    lower_ext[i] = '\0';

    // find matching MIME type
    for (size_t j = 0; j < MIME_TYPES_COUNT && mime_types[j].extension; ++j) {
        if (strcmp(lower_ext, mime_types[j].extension) == 0) {
            return (char*)mime_types[j].mime_type;
        }
    }

    return "application/octet-stream";
}

/* cleanup_resources cleans up server resources */
void cleanup_resources(void)
{
    if (g_server_config.server_socket > 0) {
        close(g_server_config.server_socket);
    }
    if (g_server_config.www_root) {
        free(g_server_config.www_root);
    }
    pthread_mutex_destroy(&thread_mutex);
    log_message("INFO", "Cleaned up resources");
}

/* main entry point */
int main(int argc, char* argv[])
{
    int port = DEFAULT_PORT;
    char* www_root = "www";

    // parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port number: %s\n", argv[i + 1]);
                exit(1);
            }
            i++;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            www_root = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-p port] [-d www_directory]\n", argv[0]);
            printf("Options:\n");
            printf("  -p port        Port to listen on (default: %d)\n", DEFAULT_PORT);
            printf("  -d directory   Web root directory (default: www)\n");
            printf("  -h, --help     Show this help message\n");
            exit(0);
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            fprintf(stderr, "Use -h or --help for usage information\n");
            exit(1);
        }
    }

    // initialize server configuration
    g_server_config.port = port;
    g_server_config.www_root = realpath(www_root, NULL);
    atomic_store(&g_server_config.shutdown_flag, 0);

    if (!g_server_config.www_root) {
        log_message("ERROR", "Cannot resolve www root path: %s - %s", www_root, strerror(errno));
        exit(1);
    }

    // Verify www_root is a directory
    struct stat root_stat;
    if (stat(g_server_config.www_root, &root_stat) != 0) {
        log_message("ERROR", "Cannot stat www root: %s - %s",
            g_server_config.www_root, strerror(errno));
        free(g_server_config.www_root);
        exit(1);
    }

    if (!S_ISDIR(root_stat.st_mode)) {
        log_message("ERROR", "www root is not a directory: %s", g_server_config.www_root);
        free(g_server_config.www_root);
        exit(1);
    }

    // setup signal handlers for graceful shutdown
    setup_signal_handlers();

    log_message("INFO", "Starting web server...");
    log_message("INFO", "Port: %d", port);
    log_message("INFO", "Document root: %s", g_server_config.www_root);

    // create and bind server socket
    g_server_config.server_socket = create_server_socket(port);
    if (g_server_config.server_socket < 0) {
        log_message("ERROR", "Failed to create server socket");
        cleanup_resources();
        exit(1);
    }

    log_message("INFO", "Server listening on port %d", port);
    log_message("INFO", "Press Ctrl+C to shutdown gracefully");

    // main server loop
    while (!atomic_load(&g_server_config.shutdown_flag)) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // accept incoming connection with non-blocking check for shutdown
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_server_config.server_socket, &read_fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int select_result = select(g_server_config.server_socket + 1, &read_fds, NULL, NULL, &tv);

        if (select_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_message("ERROR", "select() failed: %s", strerror(errno));
            break;
        }

        if (select_result == 0) {
            // Timeout, check shutdown flag
            continue;
        }

        int client_socket = accept(g_server_config.server_socket,
            (struct sockaddr*)&client_addr,
            &client_addr_len);

        if (client_socket < 0) {
            if (atomic_load(&g_server_config.shutdown_flag)) {
                break;
            }
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            log_message("ERROR", "Failed to accept connection: %s", strerror(errno));
            continue;
        }

        // check thread limit
        int current_threads = atomic_load(&active_threads);
        if (current_threads >= MAX_THREADS) {
            log_message("WARN", "Maximum threads reached (%d), rejecting connection", MAX_THREADS);
            close(client_socket);
            continue;
        }

        // create client info structure
        client_info_t* client_info = malloc(sizeof(client_info_t));
        if (!client_info) {
            log_message("ERROR", "Failed to allocate memory for client info");
            close(client_socket);
            continue;
        }

        client_info->client_socket = client_socket;
        client_info->client_addr = client_addr;
        client_info->config = &g_server_config;

        // Increment thread count before creating thread
        atomic_fetch_add(&active_threads, 1);

        // create thread to handle client
        pthread_t thread_id;
        pthread_attr_t attr;

        if (pthread_attr_init(&attr) != 0) {
            log_message("ERROR", "Failed to init thread attributes: %s", strerror(errno));
            close(client_socket);
            free(client_info);
            atomic_fetch_sub(&active_threads, 1);
            continue;
        }

        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
            log_message("ERROR", "Failed to set detached state: %s", strerror(errno));
            pthread_attr_destroy(&attr);
            close(client_socket);
            free(client_info);
            atomic_fetch_sub(&active_threads, 1);
            continue;
        }

        int thread_result = pthread_create(&thread_id, &attr, handle_client, client_info);
        pthread_attr_destroy(&attr);

        if (thread_result != 0) {
            log_message("ERROR", "Failed to create thread: %s", strerror(thread_result));
            close(client_socket);
            free(client_info);
            atomic_fetch_sub(&active_threads, 1);
            continue;
        }

        log_message("DEBUG", "Created thread for client: %s (active threads: %d)",
            inet_ntoa(client_addr.sin_addr), atomic_load(&active_threads));
    }

    log_message("INFO", "Server shutting down...");

    // Wait for active threads to complete (with timeout)
    int wait_count = 0;
    while (atomic_load(&active_threads) > 0 && wait_count < 30) {
        log_message("INFO", "Waiting for %d active threads to complete...",
            atomic_load(&active_threads));
        sleep(1);
        wait_count++;
    }

    if (atomic_load(&active_threads) > 0) {
        log_message("WARN", "Forcing shutdown with %d threads still active",
            atomic_load(&active_threads));
    }

    cleanup_resources();
    log_message("INFO", "Server stopped");

    return 0;
}
