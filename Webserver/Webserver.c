#include "Webserver.h"

/* Global server configuration */
server_config_t g_server_config = { 0 };

/* Thread pool management */
static int active_threads = 0;
static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;



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

	// remove . and .. components

	return NULL;
}
