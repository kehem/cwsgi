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
#include <sys/file.h>
#include <pthread.h>
#include <zlib.h>
#include <sys/inotify.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

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
#define MAX_VIEW_NAME 256
#define POOL_SIZE 1024
#define INOTIFY_BUFFER_SIZE (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

// Memory pool
struct memory_pool {
    void *blocks[POOL_SIZE];
    size_t block_size;
    int free_count;
    int next_free;
};

struct memory_pool client_pool;
struct memory_pool buffer_pool;

// Global variables
static volatile sig_atomic_t reload = 0;
static volatile sig_atomic_t shutdown = 0;
static pid_t *worker_pids = NULL;
static char *socket_paths[MAX_SOCKETS];
static int num_sockets = 0;
static SSL_CTX *ssl_ctx = NULL;
static PyObject *pModule = NULL, *pFunc = NULL, *start_response = NULL;
static struct event *health_check_event = NULL, *scale_check_event = NULL;
static struct event *inotify_event = NULL;
static char *wsgi_path = NULL;
static char *log_dir = NULL;
static char *config_file = NULL;
static FILE *log_file = NULL;
static int log_fd = -1;
static char current_date[11];
static int num_threads = 4;
static int use_gevent = 0;
static int reload_on_code_change = 0;
static int inotify_fd = -1;

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
struct view_metric {
    char view[MAX_VIEW_NAME];
    long count;
    double total_latency;
};
static struct view_metric *view_metrics = NULL;
static int view_metrics_count = 0;
static int view_metrics_size = 100;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

// Rate limiting
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

// Cached Python objects
static PyObject *py_request_method = NULL;
static PyObject *py_path_info = NULL;
static PyObject *py_server_name = NULL;
static PyObject *py_wsgi_url_scheme = NULL;
static PyObject *py_http_host = NULL;
static PyObject *py_remote_addr = NULL;

// Connection pool for bufferevents
struct bev_pool {
    struct bufferevent *bevs[POOL_SIZE];
    int free_count;
    int next_free;
};
static struct bev_pool bev_pool;

// Client data
struct client_data {
    struct bufferevent *bev;
    http_parser parser;
    char *buffer;
    size_t bytes_received;
    PyObject *environ;
    char *path_info;
    char *request_method;
    char *http_host;
    char *status;
    PyObject *headers;
    struct timespec start_time;
    char client_ip[8];
    int keep_alive;
    struct timeval keep_alive_timeout;
    int in_pool;
    char body[BUFFER_SIZE];
    size_t body_length;
    int is_websocket;
    char *ws_key;
};

// Memory pool functions
static void init_memory_pool(struct memory_pool *pool, size_t block_size) {
    pool->block_size = block_size;
    pool->free_count = POOL_SIZE;
    pool->next_free = 0;
    for (int i = 0; i < POOL_SIZE; i++) {
        pool->blocks[i] = malloc(block_size);
    }
}

static void *pool_alloc(struct memory_pool *pool) {
    if (pool->free_count == 0) return malloc(pool->block_size);
    pool->free_count--;
    return pool->blocks[pool->next_free++];
}

static void pool_free(struct memory_pool *pool, void *ptr) {
    if (pool->free_count < POOL_SIZE) {
        pool->blocks[pool->next_free - 1] = ptr;
        pool->free_count++;
    } else {
        free(ptr);
    }
}

static void cleanup_memory_pool(struct memory_pool *pool) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (pool->blocks[i]) free(pool->blocks[i]);
    }
}

// Connection pool functions
static void init_bev_pool(struct bev_pool *pool, struct event_base *base) {
    pool->free_count = POOL_SIZE;
    pool->next_free = 0;
    for (int i = 0; i < POOL_SIZE; i++) {
        pool->bevs[i] = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    }
}

static struct bufferevent *bev_pool_alloc(struct bev_pool *pool, struct event_base *base, int fd, SSL *ssl) {
    if (pool->free_count == 0) {
        return use_ssl ? bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE)
                       : bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    }
    pool->free_count--;
    struct bufferevent *bev = pool->bevs[pool->next_free++];
    bufferevent_setfd(bev, fd);
    if (use_ssl) {
        bufferevent_openssl_set_ssl(bev, ssl);
    }
    return bev;
}

static void bev_pool_free(struct bev_pool *pool, struct bufferevent *bev) {
    if (pool->free_count < POOL_SIZE) {
        bufferevent_setfd(bev, -1);
        pool->bevs[pool->next_free - 1] = bev;
        pool->free_count++;
    } else {
        bufferevent_free(bev);
    }
}

static void cleanup_bev_pool(struct bev_pool *pool) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (pool->bevs[i]) bufferevent_free(pool->bevs[i]);
    }
}

// Initialize SSL
static int init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) return 1;
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        return 1;
    }
    return 0;
}

// Initialize Python
static int init_python(void) {
    Py_Initialize();
    if (use_gevent) {
        PyRun_SimpleString("import gevent\n"
                           "from gevent import monkey\n"
                           "monkey.patch_all()\n");
    }

    char *wsgi_dir = strdup(wsgi_path);
    char *last_slash = strrchr(wsgi_dir, '/');
    if (last_slash) *last_slash = '\0';
    PyObject *sys_path = PySys_GetObject("path");
    PyList_Insert(sys_path, 0, PyUnicode_FromString(wsgi_dir));
    free(wsgi_dir);

    char *module_name = strrchr(wsgi_path, '/');
    module_name = module_name ? module_name + 1 : wsgi_path;
    char *dot = strrchr(module_name, '.');
    if (dot) *dot = '\0';

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
        return 1;
    }

    pFunc = PyObject_GetAttrString(pModule, "application");
    if (!pFunc || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        return 1;
    }

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

    py_request_method = PyUnicode_FromString("REQUEST_METHOD");
    py_path_info = PyUnicode_FromString("PATH_INFO");
    py_server_name = PyUnicode_FromString("SERVER_NAME");
    py_wsgi_url_scheme = PyUnicode_FromString("wsgi.url_scheme");
    py_http_host = PyUnicode_FromString("HTTP_HOST");
    py_remote_addr = PyUnicode_FromString("REMOTE_ADDR");

    return 0;
}

static void cleanup_python(void) {
    Py_XDECREF(py_request_method);
    Py_XDECREF(py_path_info);
    Py_XDECREF(py_server_name);
    Py_XDECREF(py_wsgi_url_scheme);
    Py_XDECREF(py_http_host);
    Py_XDECREF(py_remote_addr);
    Py_XDECREF(start_response);
    Py_XDECREF(pFunc);
    Py_XDECREF(pModule);
    Py_Finalize();
}

// Parse config
static int parse_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return 1;
    char line[MAX_LINE], section[MAX_LINE] = "";
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
                } else if (strcmp(key, "threads") == 0) {
                    num_threads = atoi(value);
                } else if (strcmp(key, "use_gevent") == 0) {
                    use_gevent = strcmp(value, "true") == 0;
                } else if (strcmp(key, "reload_on_code_change") == 0) {
                    reload_on_code_change = strcmp(value, "true") == 0;
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
    if (!wsgi_path || !log_dir) return 1;
    struct stat st = {0};
    if (stat(log_dir, &st) == -1) {
        if (mkdir(log_dir, 0755) == -1) return 1;
    }
    current_workers = min_workers;
    return 0;
}

// Log compression
static void compress_log_file(const char *log_path) {
    char gz_path[MAX_PATH];
    snprintf(gz_path, MAX_PATH, "%s.gz", log_path);
    FILE *in = fopen(log_path, "rb");
    if (!in) return;
    gzFile out = gzopen(gz_path, "wb");
    if (!out) {
        fclose(in);
        return;
    }
    char buf[BUFFER_SIZE];
    size_t len;
    while ((len = fread(buf, 1, BUFFER_SIZE, in)) > 0) {
        gzwrite(out, buf, len);
    }
    fclose(in);
    gzclose(out);
    unlink(log_path);
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
            flock(log_fd, LOCK_UN);
            fclose(log_file);
            close(log_fd);
            char old_log_path[MAX_PATH];
            snprintf(old_log_path, MAX_PATH, "%s/%s.log", log_dir, current_date);
            compress_log_file(old_log_path);
            log_file = NULL;
            log_fd = -1;
        }
        strcpy(current_date, new_date);
        char log_path[MAX_PATH];
        snprintf(log_path, MAX_PATH, "%s/%s.log", log_dir, current_date);
        log_fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (log_fd < 0) exit(1);
        log_file = fdopen(log_fd, "a");
        if (!log_file) {
            close(log_fd);
            exit(1);
        }
        setvbuf(log_file, NULL, _IOLBF, 0);
    }
}

static void flush_log_buffer(void) {
    if (!log_file) open_log_file();
    if (flock(log_fd, LOCK_EX) == 0) {
        for (int i = 0; i < log_count; i++) {
            fprintf(log_file, "%s\n", log_buffer[i]);
        }
        fflush(log_file);
        flock(log_fd, LOCK_UN);
    }
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

// WebSocket utilities
static void base64_encode(const unsigned char *input, int length, char *output) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);
    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';
    BIO_free_all(bio);
}

static char *compute_websocket_accept_key(const char *key) {
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[128];
    snprintf(concat, sizeof(concat), "%s%s", key, magic);
    unsigned char sha1[20];
    SHA1((unsigned char *)concat, strlen(concat), sha1);
    char *accept_key = malloc(29);
    base64_encode(sha1, 20, accept_key);
    return accept_key;
}

// HTTP parser callbacks
static int on_header_field(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    if (strncmp(at, "Host", length) == 0) {
        data->http_host = strdup("Host");
    } else if (strncmp(at, "Connection", length) == 0) {
        data->http_host = strdup("Connection");
    } else if (strncmp(at, "Upgrade", length) == 0) {
        data->http_host = strdup("Upgrade");
    } else if (strncmp(at, "Sec-WebSocket-Key", length) == 0) {
        data->http_host = strdup("Sec-WebSocket-Key");
    }
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    if (data->http_host && strcmp(data->http_host, "Host") == 0) {
        data->http_host = strndup(at, length);
    } else if (data->http_host && strcmp(data->http_host, "Connection") == 0) {
        if (strncmp(at, "keep-alive", length) == 0 || strncmp(at, "Upgrade", length) == 0) {
            data->keep_alive = 1;
            data->keep_alive_timeout.tv_sec = 15;
            data->keep_alive_timeout.tv_usec = 0;
        }
    } else if (data->http_host && strcmp(data->http_host, "Upgrade") == 0) {
        if (strncmp(at, "websocket", length) == 0) {
            data->is_websocket = 1;
        }
    } else if (data->http_host && strcmp(data->http_host, "Sec-WebSocket-Key") == 0) {
        data->ws_key = strndup(at, length);
    }
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    data->path_info = strndup(at, length);
    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length) {
    struct client_data *data = (struct client_data *)parser->data;
    if (data->body_length + length < BUFFER_SIZE) {
        memcpy(data->body + data->body_length, at, length);
        data->body_length += length;
    }
    return 0;
}

static int on_message_complete(http_parser *parser) {
    struct client_data *data = (struct client_data *)parser->data;
    data->parser.data = NULL;
    return 0;
}

// Metrics thread
static void *metrics_thread(void *arg) {
    struct event_base *base = event_base_new();
    struct sockaddr_in metrics_addr = {0};
    metrics_addr.sin_family = AF_INET;
    metrics_addr.sin_addr.s_addr = INADDR_ANY;
    metrics_addr.sin_port = htons(metrics_port);
    struct evconnlistener *listener = evconnlistener_new_bind(
        base, metrics_accept_cb, base, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *)&metrics_addr, sizeof(metrics_addr));
    if (!listener) {
        log_request("Could not create metrics listener");
        event_base_free(base);
        return NULL;
    }
    event_base_dispatch(base);
    evconnlistener_free(listener);
    event_base_free(base);
    return NULL;
}

static void metrics_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                              struct sockaddr *addr, int socklen, void *ctx) {
    struct event_base *base = (struct event_base *)ctx;
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, metrics_cb, NULL, NULL, NULL);
    bufferevent_enable(bev, EV_READ);
}

static void metrics_cb(struct bufferevent *bev, void *arg) {
    char metrics[BUFFER_SIZE * 2];
    size_t offset = 0;
    pthread_mutex_lock(&metrics_mutex);
    offset += snprintf(metrics + offset, BUFFER_SIZE * 2,
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
    for (int i = 0; i < view_metrics_count; i++) {
        offset += snprintf(metrics + offset, BUFFER_SIZE * 2 - offset,
                           "http_request_duration_seconds_per_view{view=\"%s\"} %f\n",
                           view_metrics[i].view, view_metrics[i].total_latency);
    }
    pthread_mutex_unlock(&metrics_mutex);

    char response[BUFFER_SIZE * 2];
    snprintf(response, BUFFER_SIZE * 2,
             "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nContent-Type: text/plain\r\n\r\n%s",
             strlen(metrics), metrics);
    bufferevent_write(bev, response, strlen(response));
    bufferevent_free(bev);
}

// WebSocket frame handling
static void send_websocket_frame(struct bufferevent *bev, const char *data, size_t len, int opcode) {
    unsigned char frame[BUFFER_SIZE];
    size_t offset = 0;
    frame[offset++] = 0x80 | opcode; // FIN=1, opcode
    if (len <= 125) {
        frame[offset++] = (unsigned char)len;
    } else if (len <= 65535) {
        frame[offset++] = 126;
        frame[offset++] = (len >> 8) & 0xFF;
        frame[offset++] = len & 0xFF;
    } else {
        frame[offset++] = 127;
        for (int i = 7; i >= 0; i--) {
            frame[offset++] = (len >> (i * 8)) & 0xFF;
        }
    }
    memcpy(frame + offset, data, len);
    offset += len;
    bufferevent_write(bev, frame, offset);
}

static void handle_websocket_frame(struct client_data *data, const unsigned char *buffer, size_t len) {
    if (len < 2) return;
    int fin = buffer[0] & 0x80;
    int opcode = buffer[0] & 0x0F;
    int masked = buffer[1] & 0x80;
    size_t payload_len = buffer[1] & 0x7F;
    size_t offset = 2;

    if (payload_len == 126) {
        if (len < 4) return;
        payload_len = (buffer[2] << 8) | buffer[3];
        offset = 4;
    } else if (payload_len == 127) {
        if (len < 10) return;
        payload_len = 0;
        for (int i = 2; i < 10; i++) {
            payload_len = (payload_len << 8) | buffer[i];
        }
        offset = 10;
    }

    unsigned char masking_key[4];
    if (masked) {
        if (offset + 4 > len) return;
        memcpy(masking_key, buffer + offset, 4);
        offset += 4;
    }

    if (offset + payload_len > len) return;
    char *payload = malloc(payload_len + 1);
    memcpy(payload, buffer + offset, payload_len);
    if (masked) {
        for (size_t i = 0; i < payload_len; i++) {
            payload[i] ^= masking_key[i % 4];
        }
    }
    payload[payload_len] = '\0';

    // Echo back for simplicity (replace with Django integration)
    send_websocket_frame(data->bev, payload, payload_len, opcode);
    free(payload);
}

// WSGI and WebSocket call
static void call_wsgi_app(struct client_data *data) {
    if (data->is_websocket) {
        char *accept_key = compute_websocket_accept_key(data->ws_key);
        char response[BUFFER_SIZE];
        snprintf(response, BUFFER_SIZE,
                 "HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: %s\r\n\r\n",
                 accept_key);
        bufferevent_write(data->bev, response, strlen(response));
        free(accept_key);
        log_request("WebSocket connection established: %s from %s", data->path_info, data->client_ip);
        // Switch to WebSocket mode
        bufferevent_setcb(data->bev, websocket_read_cb, NULL, event_cb, data);
        return;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();
    data->environ = PyDict_New();
    PyDict_SetItem(data->environ, py_request_method, PyUnicode_FromString(data->request_method));
    PyDict_SetItem(data->environ, py_path_info, PyUnicode_FromString(data->path_info ? data->path_info : "/"));
    PyDict_SetItem(data->environ, py_server_name, PyUnicode_FromString("localhost"));
    PyDict_SetItem(data->environ, py_wsgi_url_scheme, PyUnicode_FromString(use_ssl ? "https" : "http"));
    if (data->http_host) {
        PyDict_SetItem(data->environ, py_http_host, PyUnicode_FromString(data->http_host));
    }
    PyDict_SetItem(data->environ, py_remote_addr, PyUnicode_FromString(data->client_ip));

    PyObject *pArgs = PyTuple_Pack(2, data->environ, start_response);
    PyObject *pValue = NULL;

    if (use_gevent) {
        PyObject *gevent_module = PyImport_ImportModule("gevent");
        if (gevent_module) {
            PyObject *spawn = PyObject_GetAttrString(gevent_module, "spawn");
            PyObject *greenlet = PyObject_CallFunctionObjArgs(spawn, pFunc, pArgs, NULL);
            pValue = PyObject_CallMethod(greenlet, "get", NULL);
            Py_DECREF(greenlet);
            Py_DECREF(spawn);
            Py_DECREF(gevent_module);
        }
    } else {
        pValue = PyObject_CallObject(pFunc, pArgs);
    }
    Py_DECREF(pArgs);

    char http_response[BUFFER_SIZE];
    size_t offset = 0;

    if (pValue) {
        PyObject *status_obj = PyDict_GetItemString(PyEval_Gets(), "_status");
        PyObject *headers_obj = PyDict_GetItemString(PyEval_GetGlobals(), "_headers");
        data->status = status_obj ? strdup(PyUnicode_AsUTF8(status_obj)) : strdup("200 OK");
        data->headers = headers_obj ? headers_obj : PyList_New(0);
        Py_XINCREF(data->headers);

        offset = snprintf(http_response, BUFFER_SIZE, "HTTP/1.1 %s\r\n", data->status);
        offset += snprintf(http_response + offset, BUFFER_SIZE - offset,
                           data->keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n");

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

        pthread_mutex_lock(&metrics_mutex);
        for (int i = 0; i < view_metrics_count; i++) {
            if (strcmp(view_metrics[i].view, data->path_info) == 0) {
                view_metrics[i].count++;
                view_metrics[i].total_latency += latency;
                goto metrics_done;
            }
        }
        if (view_metrics_count >= view_metrics_size) {
            view_metrics_size *= 2;
            view_metrics = realloc(view_metrics, view_metrics_size * sizeof(struct view_metric));
        }
        strncpy(view_metrics[view_metrics_count].view, data->path_info, MAX_VIEW_NAME - 1);
        view_metrics[view_metrics_count].count = 1;
        view_metrics[view_metrics_count].total_latency = latency;
        view_metrics_count++;
metrics_done:
        pthread_mutex_unlock(&metrics_mutex);

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

// WebSocket read callback
static void websocket_read_cb(struct bufferevent *bev, void *arg) {
    struct client_data *data = (struct client_data *)arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);

    if (len > 0) {
        unsigned char *buffer = malloc(len);
        evbuffer_remove(input, buffer, len);
        handle_websocket_frame(data, buffer, len);
        free(buffer);
    }
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
                if (data->keep_alive && !data->is_websocket) {
                    http_parser_init(&data->parser, HTTP_REQUEST);
                    data->parser.data = &settings;
                    free(data->path_info);
                    free(data->http_host);
                    free(data->request_method);
                    free(data->status);
                    free(data->ws_key);
                    Py_XDECREF(data->headers);
                    Py_XDECREF(data->environ);
                    data->path_info = NULL;
                    data->http_host = NULL;
                    data->request_method = strdup(http_method_str(data->parser.method));
                    data->status = NULL;
                    data->ws_key = NULL;
                    data->headers = NULL;
                    data->environ = NULL;
                    data->keep_alive = 0;
                    data->body_length = 0;
                    bufferevent_set_timeouts(bev, &data->keep_alive_timeout, &data->keep_alive_timeout);
                    return;
                }
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
        free(data->ws_key);
        Py_XINCREF(data->headers);
        Py_XINCREF(data->environ);
        if (data->in_pool) {
            pool_free(&buffer_pool, data->buffer);
            pool_free(&client_pool, data);
        } else {
            free(data->buffer);
            free(data);
        }
        bev_pool_free(&bev_pool, bev);
    }
}

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
        free(data->ws_key);
        Py_XINCREF(data->headers);
        Py_XINCREF(data->environ);
        if (data->in_pool) {
            pool_free(&buffer_pool, data->buffer);
            pool_free(&client_pool, data);
        } else {
            free(data->buffer);
            free(data);
        }
        bev_pool_free(&bev_pool, bev);
        if (events & BEV_EVENT_TIMEOUT) {
            log_request("Connection timed out from %s", data->client_ip);
        }
    }
}

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
    SSL *ssl = use_ssl ? SSL_new(ssl_ctx) : NULL;
    bev = bev_pool_alloc(&bev_pool, base, fd, ssl);
    if (!bev) {
        log_request("Error creating bufferevent");
        close(fd);
        if (ssl) SSL_free(ssl);
        return;
    }

    struct timeval tv = { TIMEOUT_SECONDS, 0 };
    bufferevent_set_timeouts(bev, &tv, &tv);

    struct client_data *data = (struct client_data *)pool_alloc(&client_pool);
    data->buffer = (char *)pool_alloc(&buffer_pool);
    data->in_pool = 1;
    data->bev = bev;
    strcpy(data->client_ip, client_ip);
    clock_gettime(CLOCK_MONOTONIC, &data->start_time);
    http_parser_init(&data->parser, HTTP_REQUEST);
    static http_parser_settings settings = {
        .on_url = on_url,
        .on_header_field = on_header_field,
        .on_header_value = on_header_value,
        .on_body = on_body,
        .on_message_complete = on_message_complete
    };
    data->parser.data = &settings;
    data->request_method = strdup(http_method_str(data->parser.method));
    data->body_length = 0;
    data->is_websocket = 0;
    data->ws_key = NULL;

    bufferevent_setcb(bev, read_cb, NULL, event_cb, data);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// Worker thread
struct worker_thread_data {
    struct event_base *base;
    int worker_id;
    int thread_id;
};

static void *worker_thread(void *arg) {
    struct worker_thread_data *data = (struct worker_thread_data *)arg;
    struct event_base *base = data->base;

    init_bev_pool(&bev_pool, base);
    struct evconnlistener *listeners[MAX_SOCKETS];
    for (int j = 0; j < num_sockets; j++) {
        struct sockaddr_un server_addr = {0};
        server_addr.sun_family = AF_UNIX;
        strncpy(server_addr.sun_path, socket_paths[j], sizeof(server_addr.sun_path) - 1);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            log_request("Thread %d: Failed to create socket for %s", data->thread_id, socket_paths[j]);
            exit(1);
        }
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0 && data->thread_id == 0) {
            log_request("Thread %d: Failed to bind socket %s", data->thread_id, socket_paths[j]);
            close(fd);
            exit(1);
        }
        listen(fd, SOMAXCONN);
        listeners[j] = evconnlistener_new(base, accept_cb, base, LEV_OPT_CLOSE_ON_FREE, -1, fd);
        if (!listeners[j]) {
            log_request("Thread %d: Could not create listener for %s", data->thread_id, socket_paths[j]);
            close(fd);
            exit(1);
        }
    }

    log_request("Worker %d, Thread %d listening on %d sockets (%s)", data->worker_id, data->thread_id, num_sockets, use_ssl ? "https" : "http");
    event_base_dispatch(base);

    for (int j = 0; j < num_sockets; j++) {
        evconnlistener_free(listeners[j]);
    }
    cleanup_bev_pool(&bev_pool);
    event_base_free(base);
    free(data);
    return NULL;
}

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
        pthread_t threads[64];
        struct event_base *bases[64];
        struct worker_thread_data *thread_data[64];
        for (int i = 0; i < num_threads; i++) {
            bases[i] = event_base_new();
            if (!bases[i]) {
                log_request("Worker %d, Thread %d: Could not initialize libevent", worker_id, i);
                cleanup_python();
                exit(1);
            }
            thread_data[i] = malloc(sizeof(struct worker_thread_data));
            thread_data[i]->base = bases[i];
            thread_data[i]->worker_id = worker_id;
            thread_data[i]->thread_id = i;
            if (pthread_create(&threads[i], NULL, worker_thread, thread_data[i]) != 0) {
                log_request("Worker %d: Failed to create thread %d", worker_id, i);
                exit(1);
            }
        }
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        cleanup_python();
        exit(0);
    } else {
        worker_pids[worker_id] = pid;
        atomic_fetch_add(&active_workers, 1);
    }
}

// Inotify callback for code changes
static void inotify_cb(evutil_socket_t fd, short events, void *arg) {
    struct event_base *base = (struct event_base *)arg;
    char buffer[INOTIFY_BUFFER_SIZE];
    ssize_t len = read(fd, buffer, INOTIFY_BUFFER_SIZE);
    int worker_idx = 0;

    while (worker_idx < current_workers && len > 0) {
        if (worker_pids[worker_idx] > 0) {
            log_request("Detected code change, reloading worker %d", worker_idx);
            kill(worker_pids[worker_idx], SIGTERM);
            // Wait for worker to exit
            waitpid(worker_pids[worker_idx], NULL, 0);
            start_worker(base, worker_idx);
            sleep(1); // Ensure new worker binds before proceeding
        }
        worker_idx++;
    }
}

static void scale_check_cb(evutil_socket_t fd, short events, void *arg) {
    struct event_base *base = (struct event_base *)arg;
    long rps = atomic_load(&requests_per_second);
    atomic_store(&requests_per_second, 0);

    if (rps > scale_threshold_high && current_workers < max_workers) {
        int new_workers = current_workers + 1;
        log_request("Scaling up from %d to %d workers (RPS: %ld)", current_workers, new_workers, rps);
        worker_pids = realloc(worker_pids, new_workers * sizeof(pid_t));
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

static void sighup_handler(int sig) {
    reload = 1;
    for (int i = 0; i < current_workers; i++) {
        if (worker_pids[i] > 0) {
            kill(worker_pids[i], SIGTERM);
        }
    }
}

static void sigterm_handler(int sig) {
    shutdown = 1;
    for (int i = 0; i < current_workers; i++) {
        if (worker_pids[i] > 0) {
            kill(worker_pids[i], SIGTERM);
        }
    }
}

static void cleanup_zombies(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config.ini>\n", argv[0]);
        return 1;
    }
    config_file = strdup(argv[1]);
    init_memory_pool(&client_pool, sizeof(struct client_data));
    init_memory_pool(&buffer_pool, BUFFER_SIZE);
    view_metrics = malloc(view_metrics_size * sizeof(struct view_metric));
    if (parse_config(config_file)) {
        fprintf(stderr, "Failed to parse config file\n");
        return 1;
    }
    if (use_ssl && init_ssl()) {
        fprintf(stderr, "SSL initialization failed\n");
        return 1;
    }

    signal(SIGCHLD, cleanup_zombies);
    signal(SIGHUP, sighup_handler);
    signal(SIGTERM, sigterm_handler);

    worker_pids = calloc(max_workers, sizeof(pid_t));
    rate_limit_table = calloc(rate_limit_table_size, sizeof(struct rate_limit_entry *));
    if (!worker_pids || !rate_limit_table) {
        log_request("Failed to allocate memory");
        return 1;
    }

    if (reload_on_code_change) {
        inotify_fd = inotify_init1(IN_NONBLOCK);
        if (inotify_fd < 0) {
            log_request("Failed to initialize inotify");
            return 1;
        }
        if (inotify_add_watch(inotify_fd, wsgi_path, IN_MODIFY) < 0) {
            log_request("Failed to watch %s for changes", wsgi_path);
            close(inotify_fd);
            return 1;
        }
    }

    pthread_t metrics_thread_id;
    if (pthread_create(&metrics_thread_id, NULL, metrics_thread, NULL) != 0) {
        log_request("Failed to create metrics thread");
        return 1;
    }

    while (!shutdown) {
        reload = 0;
        struct event_base *base = event_base_new();
        if (!base) {
            log_request("Could not initialize libevent");
            return 1;
        }

        struct timeval health_tv = { HEALTH_CHECK_INTERVAL, 0 };
        health_check_event = event_new(base, -1, EV_TIMEOUT | EV_PERSIST, health_check_cb, base);
        event_add(health_check_event, &health_tv);

        struct timeval scale_tv = { SCALE_CHECK_INTERVAL, 0 };
        scale_check_event = event_new(base, -1, EV_TIMEOUT | EV_PERSIST, scale_check_cb, base);
        event_add(scale_check_event, &scale_tv);

        if (reload_on_code_change) {
            inotify_event = event_new(base, inotify_fd, EV_READ | EV_PERSIST, inotify_cb, base);
            event_add(inotify_event, NULL);
        }

        for (int i = 0; i < current_workers; i++) {
            start_worker(base, i);
        }

        log_request("Master process started with %d workers, %d threads each", current_workers, num_threads);
        event_base_dispatch(base);

        event_free(health_check_event);
        event_free(scale_check_event);
        if (inotify_event) event_free(inotify_event);
        event_base_free(base);

        if (!reload) break;

        log_request("Reloading workers");
        flush_log_buffer();
        free(wsgi_path);
        free(log_dir);
        for (int i = 0; i < num_sockets; i++) {
            free(socket_paths[i]);
        }
        num_sockets = 0;
        if (parse_config(config_file)) {
            log_request("Failed to reload config");
            break;
        }
    }

    if (inotify_fd >= 0) close(inotify_fd);
    flush_log_buffer();
    if (log_file) {
        flock(log_fd, LOCK_UN);
        fclose(log_file);
        close(log_fd);
    }
    free(worker_pids);
    free(wsgi_path);
    free(log_dir);
    free(config_file);
    for (int i = 0; i < num_sockets; i++) {
        free(socket_paths[i]);
    }
    cleanup_rate_limit();
    cleanup_memory_pool(&client_pool);
    cleanup_memory_pool(&buffer_pool);
    free(view_metrics);
    if (use_ssl) {
        SSL_CTX_free(ssl_ctx);
        EVP_cleanup();
    }
    return 0;
}