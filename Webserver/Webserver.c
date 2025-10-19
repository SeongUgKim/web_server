#include "Webserver.h"

#define MIME_TYPES_COUNT (sizeof(mime_types) / sizeof(mime_types[0]))

/* Global server configuration */
server_config_t g_server_config = { 0 };

/* Thread pool management */
static int active_threads = 0;
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
	{NULL, "application/octet-stream"}  // Default
};

/* log_message logs message with timestamp*/
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
	int sock_opt_res;

	// create socket
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		log_message("ERROR", "Failed to create socket: %s", strerror(errno));
		return -1;
	}
	// set socket options for address reuse
	sock_opt_res = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (sock_opt_res < 0) {
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
	sigaction(SIGINT, &sa, NULL); // Ctrl+C
	sigaction(SIGTERM, &sa, NULL); // Termination request
	sigaction(SIGPIPE, &sa, NULL); // Broken pipe
}

/* signal_handler for graceful shutdown */
void signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		log_message("INFO", "Recived signal %d, shutting down gracefully", sig);
		g_server_config.shutdown_flag = 1;
		break;
	case SIGPIPE:
		log_message("DEBUG", "Broken pipe signal ignored");
		break;
	}
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
	setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	
	// Read HTTP request
	bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
	if (bytes_received < 0) {
		log_message("WARN", "Failed to receive data from client");
		goto cleanup;
	}
	buffer[bytes_received] = '\0';
	log_message("DEBUG", "RECEIVED request: %.*s", 100, buffer);

	// parse HTTP request
	if (parse_http_request(buffer, &request) != 0) {
		log_message("WARN", "Failed to parse HTTP request");
		send_error_response(client_socket, HTTP_BAD_REQUEST);
		goto cleanup;
	}

	// only support GET method
	if (strcmp(request.method, "GET") != 0) {
		log_message("WARN", "Unsupported method: %s", request.method);
		send_Error_response(client_socket, HTTP_METHOD_NOT_ALLOWED);
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
	snprintf(full_path, sizeof(full_path), "%s%s", client_info->config->www_root, safe_path);

	// check if path is a directory and serve index.html
	struct stat path_stat;
	if(stat(full_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
		char index_path[MAX_PATH_SIZE];
		snprintf(index_path, sizeof(index_path), "%s/index.html", full_path);
		if (access(index_path, R_OK) == 0) {
			strcpy(full_path, index_path);
		} else {
			free(safe_path);
			send_error_response(client_socket, HTTP_NOT_FOUND);
			goto cleanup;
		}
	}

	// serve_file
	serve_file(client_socket, full_path);
	free(safe_path);

cleanup:
	close(client_socket);
	free(client_info);
	// decrement active thread count
	pthread_mutex_lock(&thread_mutex);
	active_threads--;
	pthread_mutex_unlock(&thread_mutex);

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
	char* token = strtok(request_line, " ");
	if (!token) {
		return -1;
	}
	strncpy(request->method, token, sizeof(request->method) - 1);

	token = strtok(NULL, " ");
	if (!token) {
		return -1;
	}
	strncpy(request->path, token, sizeof(request->path) - 1);

	token = strtok(NULL, " ");
	if (!token) {
		return -1;
	}
	strncpy(request->version, token, sizeof(request->version) - 1);

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
		body = "<html><body><h1>400 Badd Request</h1></body></html>";
	case HTTP_FORBIDDEN:
		status_text = "Forbidden";
		body = "<html><body><h1>403 Forbidden</h1></body></html>";
	case HTTP_NOT_FOUND:
		status_text = "Not Found";
		body = "<html><body><h1>404 Not Found</h1></body></html>";
	case HTTP_METHOD_NOT_ALLOWED:
		status_text = "Method Not Allowed";
		body = "<html><body><h1>405 Method Not Allowed</h1></body></html>";
	case HTTP_INTERNAL_ERROR:
		status_text = "Internal Server Error";
		body = "<html><body><h1>500 Internal Server Error</h1></body></html>";
		break;
	default:
		status_text = "Unknown Error";
		body = "<html><body><h1>Unknown Error</h1></body></html>";
	}

	send_http_response(client_socket, status_code, "text_html", body, strlen(body));
}

void send_http_response(int client_socket, int status_code, const char* content_type, const char* body, size_t body_length)
{
	char response[RESPONSE_SIZE];
	snprintf(response, sizeof(response),
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"Server: CustomWebServer/1.0\r\n"
		"\r\n",
		status_code,
		(status_code == HTTP_OK) ? "OK" : "Error",
		content_type,
		body_length);
	send(client_socket, response, strlen(response), 0);
	if (body && body_length > 0) {
		send(client_socket, body, body_length, 0);
	}
}

/* santize_path sanitizes file path to prevent directory traversal */
char* sanitize_path(const char* path)
{
	if (!path) {
		return NULL;
	}

	size_t len = strlen(path);
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
		if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
			char hex[3] = { src[1], src[2], 0 };
			*dst++ = (char)strtol(hex, NULL, 16);
			src += 3;
		}
		else {
			*dst++ = *src;
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

	//remove . and ..components
	char* components[256];
	int component_count = 0;
	char* token = strtok(sanitized, "/");
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
		token = strtok(NULL, "/");
	}

	// rebuild the path
	strcpy(sanitized, "/");
	for (int i = 0; i < component_count; ++i) {
		if (i > 0 || component_count == 0) {
			strcat(sanitized, "/");
		}
		strcat(sanitized, components[i]);
	}

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
	snprintf(full_path, sizeof(full_path), "%s%s", www_root, request_path);
	// get canonical paths
	if (!realpath(www_root, canonical_root)) {
		return 0;
	}
	// for non-existent files, check the directory portion
	char* last_slash = strrchr(full_path, '/');
	if (last_slash) {
		*last_slash = '\0';
		if (!realpath(full_path, canonical_path)) {
			return 0;
		}
		*last_slash = '/';
		strcat(canonical_path, last_slash);
	}
	else {
		if (!realpath(full_path, canonical_path)) {
			return 0;
		}
	}
	// check if canonical path starts with canonical root
	size_t root_len = strlen(canonical_root);
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
		log_message("ERROR", "Failed to open file: %s", filepath);
		send_error_response(client_socket, HTTP_INTERNAL_ERROR);
		return;
	}

	// get MIME type
	char* content_type = get_mime_type(filepath);
	// send HTTP response headers
	char header[1024];
	snprintf(header, sizeof(header),
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %ld\r\n"
		"Connection: close\r\n"
		"Server: CustomWebServer/1.0\r\n"
		"\r\n",
		content_type, file_stat.st_size);
	if (send(client_socket, header, strlen(header), 0) < 0) {
		log_message("ERROR", "Failed to send headers: %s", strerror(errno));
		close(file_fd);
		return;
	}

	// send file content using sendfile for efficiency
	off_t offset = 0;
	ssize_t sent = sendfile(client_socket, file_fd, &offset, file_stat.st_size);
	if (sent < 0) {
		log_message("ERROR", "Failed to send file content: %s", strerror(errno));
	} else {
		log_message("INFO", "Served file: %s (%ld bytes)", filepath, sent);
	}

	close(file_fd);
}

char* get_mime_type(const char* filename)
{
	if (!filename) {
		return "application/octet-stream";
	}

	const char* ext = strrchr(filename, ".");
	if (!ext) {
		return "application/octet-stream";
	}

	// convert extension to lowercase
	char lower_ext[16];
	int i;
	for (i = 0; i < sizeof(lower_ext) - 1 && ext[i]; ++i) {
		lower_ext[i] = tolower(ext[i]);
	}
	lower_ext[i] = '\0';

	// find matching MIME type
	for (int i = 0; i < MIME_TYPES_COUNT && mime_types[i].extension; ++i) {
		if (strcmp(lower_ext, mime_types[i].extension) == 0) {
			return (char*)mime_types[i].mime_type;
		}
	}

	return"application/octet-stream";
}

void cleanup_resources(void)
{
	if (g_server_config.server_socket > 0) {
		close(g_server_config.server_socket);
	}

	if (g_server_config.www_root) {
		free(g_server_config.www_root);
	}

	log_message("INFO", "Cleaned up resources");
}

int main(int argc, char* argv[])
{
	int port = DEFAULT_PORT;
	char* www_root = "www";
	// parse command line arguments
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			port = atoi(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			www_root = argv[i + 1];
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			printf("Usage: %s [-p port] [-d www_directory]\n", argv[0]);
			printf("Options:\n");
			printf("  -p port          Port to listen on (default: %d)\n", DEFAULT_PORT);
			printf("  -d directory     Web root directory (default: www)\n");
			printf("  -h, --help       Show this help message\n");
			exit(0);
		}
	}

	// initialize server configuration
	g_server_config.port = port;
	g_server_config.www_root = realpath(www_root, NULL);
	g_server_config.shutdown_flag = 0;

	if (!g_server_config.www_root) {
		log_message("ERROR", "Cannot resolve www root path: %s", www_root);
		exit(1);
	}

	// setup signal handlers for graceful shutdown
	setup_signal_handlers();
	log_message("INFO", "starting web server...");
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

	// main server loop
	while (!g_server_config.shutdown_flag) {
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		// accept incoming connection
		int client_socket = accept(g_server_config.server_socket,
			(struct sockaddr*)&client_addr, 
			&client_addr_len);
		if (client_socket < 0) {
			if (g_server_config.shutdown_flag) {
				break;
			}
			log_message("ERROR", "Failed to accept connection: %s", strerror(errno));
			continue;
		}

		// check thread limit
		pthread_mutex_lock(&thread_mutex);
		if (active_threads >= MAX_THREADS) {
			pthread_mutex_unlock(&thread_mutex);
			log_message("WARN", "Maximum threads reached, rejecting connection");
			close(client_socket);
			continue;
		}
		active_threads++;
		pthread_mutex_unlock(&thread_mutex);

		// create client info structure
		client_info_t* client_info = malloc(sizeof(client_info_t));
		if (!client_info) {
			log_message("ERROR", "Failed to allocate memory for client info");
			close(client_socket);
			pthread_mutex_lock(&thread_mutex);
			active_threads--;
			pthread_mutex_unlock(&thread_mutex);
			continue;
		}

		client_info->client_socket = client_socket;
		client_info->client_addr = client_addr;
		client_info->config = &g_server_config;

		// create thread to handle client
		pthread_t thread_id;
		int thread_result = pthread_create(&thread_id, NULL, handle_client, client_info);
		if (thread_result != 0) {
			log_message("ERROR", "Failed to create thread: %s", setrerror(thread_result));
			close(client_socket);
			free(client_info);
			pthread_mutex_lock(&thread_mutex);
			active_threads--;
			pthread_mutex_unlock(&thread_mutex);
			continue;
		}

		// detach thread for automatic cleanup
		pthread_detach(thread_id);

		log_message("DEBUG", "Create thread for client: %s", inet_ntoa(client_addr.sin_addr));
	}

	log_message("INFO", "Server shutting down...");
	cleanup_resources();

	return 0;
}
