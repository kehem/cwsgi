#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <http_parser.h>
#include <Python.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/un.h>
#include <stdatomic.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096
#define MAX_SOCKETS 16
#define TIMEOUT_SECONDS 30
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#define HEALTH_CHECK_INTERVAL 10
#define SCALE_CHECK_INTERVAL 5
#define MAX_LINE 256
#define RATE_LIMIT_WINDOW 60
#define LATENCY_BUCKETS 10
#define MAX_LOG_BATCH 100
#define MAX_PATH 1024

// Global variables
static volatile sig_atomic_t reload = 0;
static pid_t *worker_pids = NULL;
static char *socket_paths[MAX_SOCKETS];
static int num_sockets = 0;
static SSL_CTX *ssl_ctx = NULL;
static PyObject *pModule = NULL, *pFunc = NULL, *start_response = NULL;
static struct event *health_check_event = NULL, *scale_check_event = NULL;
static char *wsgi_path = NULL;
static char *log_dir = NULL;
static FILE *log_file = NULL;
static char current_date[11]; // YYYY-MM-DD

// Configuration
static int min_workers = 2;
static int max_workers = 8;
static int current_workers = 0;
static int use_ssl = 0;
static int metrics_port = 9090;
static int rate_limit = 100;
static int scale_threshold_high = 1000;
static int scale_threshold_low = 200;

// Metrics
static _Atomic long request_count = 0;
static _Atomic double total_latency = 0.0;
static long latency_buckets[LATENCY_BUCKETS] = {0};
static _Atomic long active_workers = 0;
static _Atomic long requests_per_second = 0;

// Rate limiting hash table
struct rate_limit_entry {
    char *key;
    long count;
    time_t window_start;
    struct rate_limit_entry *next;
};
static struct rate_limit_entry **rate_limit_table = NULL;
static int rate_limit_table_size = 1024;

// Log batching
static char log_buffer[MAX_LOG_BATCH][BUFFER_SIZE];
static int log_count = 0;

// Structure to hold per-connection data
struct client_data {
    struct bufferevent *bev;
    http_parser parser;
    char buffer[BUFFER_SIZE];
    size_t bytes_received;
    PyObject *environ;
    char *path_info;
    char *request_method;
    char *http_host;
    char *status;
    PyObject *headers;
    struct timespec start_time;
    char client_ip[8]; // "local" for Unix sockets
};

// Initialize SSL
static int init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load SSL certificates\n");
        return 1;
    }

    return 0;
}

// Initialize Python
static int init_python(void) {
    Py_Initialize();

    // Add wsgi_path's parent directory to sys.path
    char *wsgi_dir = strdup(wsgi_path);
    char *last_slash = strrchr(wsgi_dir, '/');
    if (last_slash) *last_slash = '\0';

    PyObject *sys_path = PySys_GetObject("path");
    PyList_Insert(sys_path, 0, PyUnicode_FromString(wsgi_dir));
    free(wsgi_dir);

    // Extract module name from wsgi_path (e.g., "wsgi" from "/path/to/wsgi.py")
    char *module_name = strrchr(wsgi_path, '/');
    module_name = module_name ? module_name + 1 : wsgi_path;
    char *dot = strrchr(module_name, '.');
    if (dot) *dot = '\0';

    // Import module (e.g., "myproject.wsgi")
    char *module_path = strdup(wsgi_path);
    for (char *p = module_path; *p; p++) {
        if (*p == '/' || *p == '.') *p = '.';
    }
    if (module_path[strlen(module_path) - 1] == '.') {
        module_path[strlen(module_path) - 1] = '\0';
    }
    PyObject *pName = PyUnicode_FromString(module_path);
    free(module_path);

    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (!pModule) {
        PyErr_Print();
        fprintf(stderr, "Failed to load WSGI module from %s\n", wsgi_path);
        return 1;
    }

    // Load 'application' callable (Django standard)
    pFunc = PyObject_GetAttrString(pModule, "application");
    if (!pFunc || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        fprintf(stderr, "Failed to load 'application' callable from %s\n", wsgi_path);
        return 1;
    }

    // Define start_response
    PyObject *code = Py_CompileString(
        "def start_response(status, headers):\n"
        "    global _status, _headers\n"
        "    _status = status\n"
        "    _headers = headers\n",
        "<string>", Py_file_input);
    PyObject *module = PyImport_ExecCodeModule("start_response_module", code);
    Py_DECREF(code);
    start_response = PyObject_GetAttrString(module, "start_response");
    Py_DECREF(module);

    return 0;
}

// Clean up Python
static void cleanup_python(void) {
    Py_XDECREF(start_response);
    Py_XDECREF(pFunc);
    Py_XDECREF(pModule);
    Py_Finalize();
}

// Parse INI configuration
static int parse_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open config file: %s\n", filename);
        return 1;
    }

    char line[MAX_LINE];
    char section[MAX_LINE] = "";
    while (fgets(line, MAX_LINE, file)) {
        line[strcspn(line, "\n")] = 0;
        char *trimmed = line;
        while (*trimmed == ' ') trimmed++;
        if (strlen(trimmed) == 0 || trimmed[0] == '#') continue;

        if (trimmed[0] == '[') {
            sscanf(trimmed, "[%[^]]]", section);
            continue;
        }

        char key[MAX_LINE], value[MAX_PATH];
        if (sscanf(trimmed, "%[^=]=%s", key, value) == 2) {
            while (key[strlen(key) - 1] == ' ') key[strlen(key) - 1] = 0;
            while (value[0] == ' ') memmove(value, value + 1, strlen(value));

            if (strcmp(section, "server") == 0) {
                if (strcmp(key, "sockets") == 0) {
                    char *token = strtok(value, ",");
                    while (token && num_sockets < MAX_SOCKETS) {
                        socket_paths[num_sockets++] = strdup(token);
                        token = strtok(NULL, ",");
                    }
                } else if (strcmp(key, "min_workers") == 0) {
                    min_workers = atoi(value);
                } else if (strcmp(key, "max_workers") == 0) {
                    max_workers = atoi(value);
                } else if (strcmp(key, "ssl") == 0) {
                    use_ssl = strcmp(value, "true") == 0;
                } else if (strcmp(key, "metrics_port") == 0) {
                    metrics_port = atoi(value);
                } else if (strcmp(key, "rate_limit") == 0) {
                    rate_limit = atoi(value);
                } else if (strcmp(key, "scale_threshold_high") == 0) {
                    scale_threshold_high = atoi(value);
                } else if (strcmp(key, "scale_threshold_low") == 0) {
                    scale_threshold_low = atoi(value);
                } else if (strcmp(key, "wsgi_path") == 0) {
                    wsgi_path = strdup(value);
                } else if (strcmp(key, "log_dir") == 0) {
                    log_dir = strdup(value);
                }
            }
        }
    }

    fclose(file);
    if (num_sockets == 0) socket_paths[num_sockets++] = strdup("/tmp/wsgi.sock");
    if (!wsgi_path) {
        fprintf(stderr, "wsgi_path not specified in config\n");
        return 1;
    }
    if (!log_dir) {
        fprintf(stderr, "log_dir not specified in config\n");
        return 1;
    }
    // Ensure log directory exists
    struct stat st = {0};
    if (stat(log_dir, &st) == -1) {
        if (mkdir(log_dir, 0755) == -1) {
            fprintf(stderr, "Failed to create log directory %s\n", log_dir);
            return 1;
        }
    }
    current_workers = min_workers;
    return 0;
}

// Log file management
static void open_log_file(void) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char new_date[11];
    strftime(new_date, sizeof(new_date), "%Y-%m-%d", tm);

    if (strcmp(new_date, current_date) != 0 || !log_file) {
        if (log_file) {
            flush_log_buffer();
            fclose(log_file);
            log_file = NULL;
        }

        strcpy(current_date, new_date);
        char log_path[MAX_PATH];
        snprintf(log_path, MAX_PATH, "%s/%s.log", log_dir, current_date);

        log_file = fopen(log_path, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file %s\n", log_path);
            exit(1);
        }
        setvbuf(log_file, NULL, _IOLBF, 0); // Line-buffered
    }
}

// Rate limiting
static unsigned int hash_key(const char *key) {
    unsigned int hash = 5381;
    while (*key) hash = ((hash << 5) + hash) + *key++;
    return hash % rate_limit_table_size;
}

static int check_rate_limit(const char *key) {
    if (!rate_limit) return 1;

    unsigned int index = hash_key(key);
    time_t now = time(NULL);
    struct rate_limit_entry *entry = rate_limit_table[index];

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (now - entry->window_start >= RATE_LIMIT_WINDOW) {
                entry->count = 1;
                entry->window_start = now;
                return 1;
            }
            if (entry->count >= rate_limit) return 0;
            entry->count++;
            return 1;
        }
        entry = entry->next;
    }

    entry = (struct rate_limit_entry *)calloc(1, sizeof(struct rate_limit_entry));
    entry->key = strdup(key);
    entry->count = 1;
    entry->window_start = now;
    entry->next = rate_limit_table[index];
    rate_limit_table[index] = entry;
    return 1;
}

static void cleanup_rate_limit(void) {
    for (int i = 0; i < rate_limit_table_size; i++) {
        struct rate_limit_entry *entry = rate_limit_table[i];
        while (entry) {
            struct rate_limit_entry *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(rate_limit_table);
}

// Batch logging
static void flush_log_buffer(void) {
    if (!log_file) open_log_file();
    for (int i = 0; i < log_count; i++) {
        fprintf(log_file, "%s\n", log_buffer[i]);
    }
    fflush(log_file);
    log_count = 0;
}

static void log_request(const char *fmt, ...) {
    open_log_file();
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    char message[BUFFER_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, BUFFER_SIZE, fmt, args);
    va_end(args);

    snprintf(log_buffer[log_count], BUFFER_SIZE, "[%s] %s", timestamp, message);
    if (++log_count >= MAX_LOG_BATCH) flush_log_buffer();
}

// HTTP parser callbacks
static int on_url(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    data->path_info = strndup(at, length);
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    if (strncmp(at, "Host", length) == 0) {
        data->http_host = strdup("Host");
    }
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    if (data->http_host && strcmp(data->http_host, "Host") == 0) {
        data->http_host = strndup(at, length);
    }
    return 0;
}

static int on_message_complete(http_parser *parser) {
    struct client_data *data = (struct client_data *)parser->data;
    data->parser.data = NULL;
    return 0;
}

// Metrics endpoint
static void metrics_cb(struct bufferevent *bev, void *arg) {
    char metrics[BUFFER_SIZE * 2];
    size_t offset = snprintf(metrics, BUFFER_SIZE * 2,
                             "# HELP http_requests_total Total number of HTTP requests\n"
                             "# TYPE http_requests_total counter\n"
                             "http_requests_total %ld\n"
                             "# HELP http_request_duration_seconds Histogram of request latencies\n"
                             "# TYPE http_request_duration_seconds histogram\n"
                             "http_request_duration_seconds_sum %f\n"
                             "http_request_duration_seconds_count %ld\n"
                             "# HELP active_workers Number of active workers\n"
                             "# TYPE active_workers gauge\n"
                             "active_workers %ld\n"
                             "# HELP requests_per_second Current request rate\n"
                             "# TYPE requests_per_second gauge\n"
                             "requests_per_second %ld\n",
                             request_count, total_latency, request_count, active_workers, requests_per_second);

    for (int i = 0; i < LATENCY_BUCKETS; i++) {
        offset += snprintf(metrics + offset, BUFFER_SIZE * 2 - offset,
                           "http_request_duration_seconds_bucket{le=\"%d\"} %ld\n",
                           i + 1, latency_buckets[i]);
    }

    char response[BUFFER_SIZE * 2];
    snprintf(response, BUFFER_SIZE * 2,
             "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nContent-Type: text/plain\r\n\r\n%s",
             strlen(metrics), metrics);
    bufferevent_write(bev, response, strlen(response));
    bufferevent_free(bev);
}

// Metrics listener callback
static void metrics_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                             struct sockaddr *addr, int socklen, void *ctx) {
    struct event_base *base = (struct event_base *)ctx;
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        log_request("Error creating metrics bufferevent");
        close(fd);
        return;
    }
    bufferevent_setcb(bev, metrics_cb, NULL, NULL, NULL);
    bufferevent_enable(bev, EV_READ);
}

// WSGI call
static void call_wsgi_app(struct client_data *data) {
    PyGILState_STATE gstate = PyGILState_Ensure();

    data->environ = PyDict_New();
    PyDict_SetItemString(data->environ, "REQUEST_METHOD", PyUnicode_FromString(data->request_method));
    PyDict_SetItemString(data->environ, "PATH_INFO", PyUnicode_FromString(data->path_info ? data->path_info : "/"));
    PyDict_SetItemString(data->environ, "SERVER_NAME", PyUnicode_FromString("localhost"));
    PyDict_SetItemString(data->environ, "wsgi.url_scheme", PyUnicode_FromString(use_ssl ? "https" : "http"));
    if (data->http_host) {
        PyDict_SetItemString(data->environ, "HTTP_HOST", PyUnicode_FromString(data->http_host));
    }
    PyDict_SetItemString(data->environ, "REMOTE_ADDR", PyUnicode_FromString(data->client_ip));

    PyObject *pArgs = PyTuple_Pack(2, data->environ, start_response);
    PyObject *pValue = PyObject_CallObject(pFunc, pArgs);
    Py_DECREF(pArgs);

    char http_response[BUFFER_SIZE];
    size_t offset = 0;

    if (pValue) {
        PyObject *status_obj = PyDict_GetItemString(PyEval_GetGlobals(), "_status");
        PyObject *headers_obj = PyDict_GetItemString(PyEval_GetGlobals(), "_headers");
        data->status = status_obj ? strdup(PyUnicode_AsUTF8(status_obj)) : strdup("200 OK");
        data->headers = headers_obj ? headers_obj : PyList_New(0);
        Py_XINCREF(data->headers);

        offset = snprintf(http_response, BUFFER_SIZE, "HTTP/1.1 %s\r\n", data->status);

        for (Py_ssize_t i = 0; i < PyList_Size(data->headers); i++) {
            PyObject *header = PyList_GetItem(data->headers, i);
            PyObject *key = PyTuple_GetItem(header, 0);
            PyObject *value = PyTuple_GetItem(header, 1);
            offset += snprintf(http_response + offset, BUFFER_SIZE - offset,
                               "%s: %s\r\n", PyUnicode_AsUTF8(key), PyUnicode_AsUTF8(value));
        }

        const char *response_body = PyUnicode_AsUTF8(pValue);
        offset += snprintf(http_response + offset, BUFFER_SIZE - offset,
                           "Content-Length: %zu\r\n\r\n%s", strlen(response_body), response_body);

        bufferevent_write(data->bev, http_response, offset);

        struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double latency = (end_time.tv_sec - data->start_time.tv_sec) +
                         (end_time.tv_nsec - data->start_time.tv_nsec) / 1e9;
        atomic_fetch_add(&request_count, 1);
        atomic_fetch_add(&total_latency, latency);
        atomic_fetch_add(&requests_per_second, 1);
        int bucket = (int)(latency * 1000);
        if (bucket < LATENCY_BUCKETS) latency_buckets[bucket]++;

        log_request("Request: %s %s from %s, Status: %s, Latency: %.3fms",
                    data->request_method, data->path_info, data->client_ip, data->status, latency * 1000);

        Py_DECREF(pValue);
    } else {
        PyErr_Print();
        const char *error = "HTTP/1.1 500 Internal Server Error\r\n\r\nServer Error";
        bufferevent_write(data->bev, error, strlen(error));
        log_request("Request failed: %s %s from %s", data->request_method, data->path_info, data->client_ip);
    }

    PyGILState_Release(gstate);
}

// Read callback
static void read_cb(struct bufferevent *bev, void *arg) {
    struct client_data *data = (struct client_data *)arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);

    if (len > 0) {
        data->bytes_received = evbuffer_remove(input, data->buffer, BUFFER_SIZE - 1);
        data->buffer[data->bytes_received] = '\0';

        if (data->parser.data) {
            size_t nparsed = http_parser_execute(&data->parser, (http_parser_settings *)data->parser.data,
                                                data->buffer, data->bytes_received);
            if (data->parser.http_errno != HPE_OK) {
                const char *error = "HTTP/1.1 400 Bad Request\r\n\r\nBad Request";
                bufferevent_write(bev, error, strlen(error));
                log_request("Invalid request from %s", data->client_ip);
                goto cleanup;
            }

            if (!data->parser.data) {
                call_wsgi_app(data);
                goto cleanup;
            }
        }
        return;

    cleanup:
        if (data->parser.data) {
            free(data->parser.data);
        }
        free(data->path_info);
        free(data->http_host);
        free(data->request_method);
        free(data->status);
        Py_XDECREF(data->headers);
        Py_XDECREF(data->environ);
        bufferevent_free(bev);
        free(data);
    }
}

// Event callback
static void event_cb(struct bufferevent *bev, short events, void *arg) {
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        struct client_data *data = (struct client_data *)arg;
        if (data->parser.data) {
            free(data->parser.data);
        }
        free(data->path_info);
        free(data->http_host);
        free(data->request_method);
        free(data->status);
        Py_XDECREF(data->headers);
        Py_XDECREF(data->environ);
        bufferevent_free(bev);
        free(data);
        if (events & BEV_EVENT_TIMEOUT) {
            log_request("Connection timed out from %s", data->client_ip);
        }
    }
}

// Accept callback
static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *addr, int socklen, void *ctx) {
    struct event_base *base = (struct event_base *)ctx;

    const char *client_ip = "local";
    if (!check_rate_limit(client_ip)) {
        const char *error = "HTTP/1.1 429 Too Many Requests\r\n\r\nRate Limit Exceeded";
        write(fd, error, strlen(error));
        close(fd);
        log_request("Rate limit exceeded for %s", client_ip);
        return;
    }

    struct bufferevent *bev;
    if (use_ssl) {
        SSL *ssl = SSL_new(ssl_ctx);
        bev = bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
    } else {
        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    }

    if (!bev) {
        log_request("Error creating bufferevent");
        close(fd);
        return;
    }

    struct timeval tv = { TIMEOUT_SECONDS, 0 };
    bufferevent_set_timeouts(bev, &tv, &tv);

    struct client_data *data = (struct client_data *)calloc(1, sizeof(struct client_data));
    if (!data) {
        log_request("Error allocating client data");
        bufferevent_free(bev);
        return;
    }
    data->bev = bev;
    strcpy(data->client_ip, client_ip);
    clock_gettime(CLOCK_MONOTONIC, &data->start_time);

    http_parser_init(&data->parser, HTTP_REQUEST);
    static http_parser_settings settings = {
        .on_url = on_url,
        .on_header_field = on_header_field,
        .on_header_value = on_header_value,
        .on_message_complete = on_message_complete
    };
    data->parser.data = &settings;
    data->request_method = strdup(http_method_str(data->parser.method));

    bufferevent_setcb(bev, read_cb, NULL, event_cb, data);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// Worker initialization
static void start_worker(struct event_base *base, int worker_id) {
    pid_t pid = fork();
    if (pid < 0) {
        log_request("Fork failed for worker %d", worker_id);
        return;
    }
    if (pid == 0) {
        if (init_python()) {
            log_request("Failed to initialize Python");
            exit(1);
        }

        base = event_base_new();
        if (!base) {
            log_request("Could not initialize libevent");
            cleanup_python();
            exit(1);
        }

        struct evconnlistener *listeners[MAX_SOCKETS];
        for (int j = 0; j < num_sockets; j++) {
            struct sockaddr_un server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sun_family = AF_UNIX;
            strncpy(server_addr.sun_path, socket_paths[j], sizeof(server_addr.sun_path) - 1);
            if (worker_id == 0) unlink(socket_paths[j]); // Only first worker unlinks

            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) {
                log_request("Failed to create socket for %s", socket_paths[j]);
                exit(1);
            }

            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                log_request("Failed to bind socket %s", socket_paths[j]);
                close(fd);
                exit(1);
            }

            listen(fd, SOMAXCONN);
            listeners[j] = evconnlistener_new(base, accept_cb, base, LEV_OPT_CLOSE_ON_FREE, -1, fd);
            if (!listeners[j]) {
                log_request("Could not create listener for %s", socket_paths[j]);
                close(fd);
                exit(1);
            }
        }

        log_request("Worker %d listening on %d sockets (%s)", getpid(), num_sockets, use_ssl ? "https" : "http");
        event_base_dispatch(base);

        for (int j = 0; j < num_sockets; j++) {
            evconnlistener_free(listeners[j]);
        }
        event_base_free(base);
        cleanup_python();
        exit(0);
    } else {
        worker_pids[worker_id] = pid;
        atomic_fetch_add(&active_workers, 1);
    }
}

// Dynamic worker scaling
static void scale_check_cb(evutil_socket_t fd, short events, void *arg) {
    struct event_base *base = (struct event_base *)arg;
    long rps = atomic_load(&requests_per_second);
    atomic_store(&requests_per_second, 0);

    if (rps > scale_threshold_high && current_workers < max_workers) {
        int new_workers = current_workers + 1;
        log_request("Scaling up from %d to %d workers (RPS: %ld)", current_workers, new_workers, rps);
        worker_pids = (pid_t *)realloc(worker_pids, new_workers * sizeof(pid_t));
        start_worker(base, current_workers);
        current_workers = new_workers;
    } else if (rps < scale_threshold_low && current_workers > min_workers) {
        int new_workers = current_workers - 1;
        log_request("Scaling down from %d to %d workers (RPS: %ld)", current_workers, new_workers, rps);
        if (worker_pids[new_workers] > 0) {
            kill(worker_pids[new_workers], SIGTERM);
            atomic_fetch_sub(&active_workers, 1);
        }
        current_workers = new_workers;
    }
}

// Health check callback
static void health_check_cb(evutil_socket_t fd, short events, void *arg) {
    struct event_base *base = (struct event_base *)arg;
    atomic_store(&active_workers, 0);

    for (int i = 0; i < current_workers; i++) {
        if (worker_pids[i] > 0 && kill(worker_pids[i], 0) == 0) {
            atomic_fetch_add(&active_workers, 1);
            continue;
        }

        log_request("Worker %d failed, restarting", worker_pids[i]);
        start_worker(base, i);
    }
}

// Signal handler for graceful reload
static void sighup_handler(int sig) {
    reload = 1;
    for (int i = 0; i < current_workers; i++) {
        if (worker_pids[i] > 0) {
            kill(worker_pids[i], SIGTERM);
        }
    }
}

// Clean up zombies
static void cleanup_zombies(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config.ini>\n", argv[0]);
        return 1;
    }

    if (parse_config(argv[1])) {
        fprintf(stderr, "Failed to parse config file\n");
        return 1;
    }

    if (use_ssl && init_ssl()) {
        fprintf(stderr, "SSL initialization failed\n");
        return 1;
    }

    signal(SIGCHLD, cleanup_zombies);
    signal(SIGHUP, sighup_handler);

    worker_pids = (pid_t *)calloc(max_workers, sizeof(pid_t));
    if (!worker_pids) {
        log_request("Failed to allocate worker PIDs");
        return 1;
    }

    rate_limit_table = (struct rate_limit_entry **)calloc(rate_limit_table_size, sizeof(struct rate_limit_entry *));
    if (!rate_limit_table) {
        log_request("Failed to allocate rate limit table");
        return 1;
    }

    while (1) {
        reload = 0;

        struct event_base *base = event_base_new();
        if (!base) {
            log_request("Could not initialize libevent");
            return 1;
        }

        struct sockaddr_in metrics_addr;
        memset(&metrics_addr, 0, sizeof(metrics_addr));
        metrics_addr.sin_family = AF_INET;
        metrics_addr.sin_addr.s_addr = INADDR_ANY;
        metrics_addr.sin_port = htons(metrics_port);

        struct evconnlistener *metrics_listener = evconnlistener_new_bind(
            base, metrics_accept_cb, base,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
            (struct sockaddr *)&metrics_addr, sizeof(metrics_addr));

        if (!metrics_listener) {
            log_request("Could not create metrics listener");
            event_base_free(base);
            return 1;
        }

        struct timeval health_tv = { HEALTH_CHECK_INTERVAL, 0 };
        health_check_event = event_new(base, -1, EV_TIMEOUT | EV_PERSIST, health_check_cb, base);
        event_add(health_check_event, &health_tv);

        struct timeval scale_tv = { SCALE_CHECK_INTERVAL, 0 };
        scale_check_event = event_new(base, -1, EV_TIMEOUT | EV_PERSIST, scale_check_cb, base);
        event_add(scale_check_event, &scale_tv);

        for (int i = 0; i < current_workers; i++) {
            start_worker(base, i);
        }

        log_request("Master process started with %d workers", current_workers);
        event_base_dispatch(base);

        event_free(health_check_event);
        event_free(scale_check_event);
        evconnlistener_free(metrics_listener);
        event_base_free(base);

        if (!reload) break;

        log_request("Reloading workers");
        flush_log_buffer();
    }

    flush_log_buffer();
    if (log_file) fclose(log_file);
    free(worker_pids);
    free(wsgi_path);
    free(log_dir);
    for (int i = 0; i < num_sockets; i++) {
        free(socket_paths[i]);
    }
    cleanup_rate_limit();
    if (use_ssl) {
        SSL_CTX_free(ssl_ctx);
        EVP_cleanup();
    }
    return 0;
}