/*
 * SIMPLE PACKET FILTER / FIREWALL RULES ENGINE
 * Educational C backend using Winsock (Windows).
 * This server simulates packet inspection; it does not alter the OS firewall.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#define PORT 8080
#define BUF_SIZE 16384
#define MAX_RULES 100
#define MAX_REQUESTS_PER_MINUTE 1200

typedef struct {
    int id;
    char name[64];
    char protocol[12];
    int port;                 /* 0 means any port */
    char action[8];           /* ALLOW or BLOCK */
    int enabled;
} FirewallRule;

static FirewallRule rules[MAX_RULES] = {
    {1, "Allow HTTPS traffic", "TCP", 443, "ALLOW", 1},
    {2, "Allow HTTP traffic", "TCP", 80, "ALLOW", 1},
    {3, "Allow DNS queries", "UDP", 53, "ALLOW", 1},
    {4, "Block Telnet", "TCP", 23, "BLOCK", 1},
    {5, "Block suspicious port", "TCP", 8081, "BLOCK", 1}
};
static int rule_count = 5;
static int next_id = 6;
static unsigned long total_packets = 0, allowed_packets = 0, blocked_packets = 0;
static time_t request_window_start;
static unsigned long requests_in_window;

static int send_all(SOCKET client, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        int result = send(client, data + sent, (int)(length - sent), 0);
        if (result <= 0) return 0;
        sent += (size_t)result;
    }
    return 1;
}

static void send_response(SOCKET client, const char *status, const char *type, const char *body) {
    char header[512];
    int len = (int)strlen(body);
    snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        status, type, len);
    if (!send_all(client, header, strlen(header))) return;
    send_all(client, body, (size_t)len);
}

static int header_name_equals(const char *name, size_t length, const char *expected) {
    size_t expected_length = strlen(expected);
    if (length != expected_length) return 0;
    for (size_t i = 0; i < length; i++) {
        if (tolower((unsigned char)name[i]) != tolower((unsigned char)expected[i])) return 0;
    }
    return 1;
}

static int get_request_body_length(const char *request, size_t header_length, size_t *body_length) {
    const char *line = strstr(request, "\r\n");
    if (!line) return 0;
    line += 2;
    const char *headers_end = request + header_length - 2;
    int found_length = 0;
    *body_length = 0;

    while (line < headers_end) {
        const char *line_end = strstr(line, "\r\n");
        if (!line_end || line_end > headers_end) return 0;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (colon) {
            size_t name_length = (size_t)(colon - line);
            const char *value = colon + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) value++;
            if (header_name_equals(line, name_length, "Content-Length")) {
                if (found_length) return 0;
                errno = 0;
                char *value_end;
                unsigned long parsed = strtoul(value, &value_end, 10);
                if (value_end == value || errno == ERANGE || parsed >= BUF_SIZE) return 0;
                while (value_end < line_end && (*value_end == ' ' || *value_end == '\t')) value_end++;
                if (value_end != line_end) return 0;
                *body_length = (size_t)parsed;
                found_length = 1;
            } else if (header_name_equals(line, name_length, "Transfer-Encoding")) {
                return 0;
            }
        }
        line = line_end + 2;
    }
    return 1;
}

static int receive_request(SOCKET client, char *request, size_t capacity) {
    size_t received = 0, header_length = 0, body_length = 0;
    while (received < capacity - 1) {
        int count = recv(client, request + received, (int)(capacity - received - 1), 0);
        if (count <= 0) return 0;
        received += (size_t)count;
        request[received] = '\0';

        if (!header_length) {
            char *headers_end = strstr(request, "\r\n\r\n");
            if (headers_end) {
                header_length = (size_t)(headers_end - request) + 4;
                if (!get_request_body_length(request, header_length, &body_length) ||
                    body_length > capacity - header_length - 1) return 0;
            }
        }
        if (header_length && received >= header_length + body_length) return 1;
    }
    return 0;
}

static void json_escape_copy(char *out, size_t cap, const char *in) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < cap; i++) {
        if (in[i] == '"' || in[i] == '\\') out[j++] = '\\';
        if ((unsigned char)in[i] >= 32) out[j++] = in[i];
    }
    out[j] = '\0';
}

static void get_string(const char *body, const char *key, char *out, size_t cap, const char *fallback) {
    char pattern[80];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(body, pattern);
    if (!p) { snprintf(out, cap, "%s", fallback); return; }
    p = strchr(p, ':');
    if (!p) { snprintf(out, cap, "%s", fallback); return; }
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i + 1 < cap) {
            unsigned char ch = (unsigned char)*p++;
            if (ch == '\\') {
                ch = (unsigned char)*p++;
                switch (ch) {
                    case '"': case '\\': case '/': break;
                    case 'b': ch = '\b'; break;
                    case 'f': ch = '\f'; break;
                    case 'n': ch = '\n'; break;
                    case 'r': ch = '\r'; break;
                    case 't': ch = '\t'; break;
                    default:
                        snprintf(out, cap, "%s", fallback);
                        return;
                }
            } else if (ch < 32) {
                snprintf(out, cap, "%s", fallback);
                return;
            }
            out[i++] = (char)ch;
        }
        if (*p != '"') {
            snprintf(out, cap, "%s", fallback);
            return;
        }
        out[i] = '\0';
    } else {
        snprintf(out, cap, "%s", fallback);
    }
}

static int get_int(const char *body, const char *key, int fallback) {
    char pattern[80];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(body, pattern);
    if (!p || !(p = strchr(p, ':'))) return fallback;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    errno = 0;
    char *end;
    long value = strtol(p, &end, 10);
    if (p == end || errno == ERANGE || value < -1 || value > 65535) return fallback;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') end++;
    if (*end != ',' && *end != '}') return fallback;
    return (int)value;
}

static int valid_protocol(const char *protocol, int allow_any) {
    return strcmp(protocol, "TCP") == 0 || strcmp(protocol, "UDP") == 0 ||
           (!allow_any && strcmp(protocol, "ICMP") == 0) ||
           (allow_any && strcmp(protocol, "ANY") == 0);
}

static int valid_ipv4(const char *address) {
    struct in_addr parsed;
    return inet_pton(AF_INET, address, &parsed) == 1;
}

static int allow_request(void) {
    time_t now = time(NULL);
    if (now == (time_t)-1) return 0;
    if (now - request_window_start >= 60 || now < request_window_start) {
        request_window_start = now;
        requests_in_window = 0;
    }
    if (requests_in_window >= MAX_REQUESTS_PER_MINUTE) return 0;
    requests_in_window++;
    return 1;
}

static void rules_json(char *out, size_t cap) {
    size_t used = 0;
    used += snprintf(out + used, cap - used, "{\"rules\":[");
    for (int i = 0; i < rule_count; i++) {
        FirewallRule *r = &rules[i];
        char name[128]; json_escape_copy(name, sizeof(name), r->name);
        used += snprintf(out + used, cap - used,
            "%s{\"id\":%d,\"name\":\"%s\",\"protocol\":\"%s\",\"port\":%d,\"action\":\"%s\",\"enabled\":%s}",
            i ? "," : "", r->id, name, r->protocol, r->port, r->action, r->enabled ? "true" : "false");
        if (used >= cap - 256) break;
    }
    snprintf(out + used, cap - used, "]}");
}

static void evaluate_packet(SOCKET client, const char *body) {
    char protocol[16], src[64], dst[64], result[16] = "BLOCK";
    get_string(body, "protocol", protocol, sizeof(protocol), "");
    get_string(body, "sourceIp", src, sizeof(src), "");
    get_string(body, "destinationIp", dst, sizeof(dst), "");
    int port = get_int(body, "port", -1);
    if (!valid_protocol(protocol, 0) || !valid_ipv4(src) || !valid_ipv4(dst) ||
        port < 0 || port > 65535) {
        send_response(client, "400 Bad Request", "application/json",
                      "{\"error\":\"Invalid protocol, IPv4 address, or port\"}");
        return;
    }
    int matched = 0, matched_id = 0;
    for (int i = 0; i < rule_count; i++) {
        FirewallRule *r = &rules[i];
        if (!r->enabled) continue;
        if ((strcmp(r->protocol, "ANY") == 0 || strcmp(r->protocol, protocol) == 0) &&
            (r->port == 0 || r->port == port)) {
            snprintf(result, sizeof(result), "%s", r->action);
            matched = 1; matched_id = r->id;
            break;
        }
    }
    total_packets++;
    if (strcmp(result, "ALLOW") == 0) allowed_packets++; else blocked_packets++;
    char safe_src[128], safe_dst[128];
    json_escape_copy(safe_src, sizeof(safe_src), src);
    json_escape_copy(safe_dst, sizeof(safe_dst), dst);
    char response[1024];
    snprintf(response, sizeof(response),
        "{\"action\":\"%s\",\"matched\":%s,\"ruleId\":%d,\"protocol\":\"%s\",\"port\":%d,"
        "\"sourceIp\":\"%s\",\"destinationIp\":\"%s\",\"message\":\"%s\"}",
        result, matched ? "true" : "false", matched_id, protocol, port, safe_src, safe_dst,
        matched ? "Packet matched a firewall rule." : "No matching rule. Default policy: BLOCK.");
    send_response(client, "200 OK", "application/json", response);
}

static void serve_static(SOCKET client, const char *path) {
    const char *file_path, *content_type;
    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        file_path = "public\\index.html";
        content_type = "text/html; charset=utf-8";
    } else if (strcmp(path, "/style.css") == 0) {
        file_path = "public\\style.css";
        content_type = "text/css; charset=utf-8";
    } else if (strcmp(path, "/app.js") == 0) {
        file_path = "public\\app.js";
        content_type = "text/javascript; charset=utf-8";
    } else {
        send_response(client, "404 Not Found", "application/json", "{\"error\":\"Not found\"}");
        return;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        send_response(client, "500 Internal Server Error", "application/json",
                      "{\"error\":\"Dashboard file unavailable\"}");
        return;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        send_response(client, "500 Internal Server Error", "application/json",
                      "{\"error\":\"Dashboard file unavailable\"}");
        return;
    }
    long file_size = ftell(file);
    if (file_size < 0 || file_size > 262144 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        send_response(client, "500 Internal Server Error", "application/json",
                      "{\"error\":\"Dashboard file size is invalid\"}");
        return;
    }
    char *contents = (char *)malloc((size_t)file_size);
    if (!contents || fread(contents, 1, (size_t)file_size, file) != (size_t)file_size) {
        free(contents);
        fclose(file);
        send_response(client, "500 Internal Server Error", "application/json",
                      "{\"error\":\"Dashboard file could not be read\"}");
        return;
    }
    fclose(file);

    char header[1024];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
        "X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        content_type, file_size);
    if (header_len > 0 && (size_t)header_len < sizeof(header))
        send_all(client, header, (size_t)header_len);
    if (file_size > 0) send_all(client, contents, (size_t)file_size);
    free(contents);
}

static void handle_client(SOCKET client) {
    char request[BUF_SIZE];
    DWORD timeout_ms = 5000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    if (!receive_request(client, request, sizeof(request))) {
        send_response(client, "400 Bad Request", "application/json", "{\"error\":\"Invalid or oversized request\"}");
        closesocket(client);
        return;
    }

    char method[12] = {0}, path[256] = {0};
    sscanf(request, "%11s %255s", method, path);

    if (!allow_request()) {
        send_response(client, "429 Too Many Requests", "application/json",
                      "{\"error\":\"Request rate limit reached\"}");
    } else if (strcmp(path, "/api/stats") == 0 && strcmp(method, "GET") == 0) {
        char body[256];
        snprintf(body, sizeof(body), "{\"total\":%lu,\"allowed\":%lu,\"blocked\":%lu}",
                 total_packets, allowed_packets, blocked_packets);
        send_response(client, "200 OK", "application/json", body);
    } else if (strcmp(path, "/api/rules") == 0 && strcmp(method, "GET") == 0) {
        char body[12000]; rules_json(body, sizeof(body));
        send_response(client, "200 OK", "application/json", body);
    } else if (strcmp(path, "/api/evaluate") == 0 && strcmp(method, "POST") == 0) {
        char *body = strstr(request, "\r\n\r\n");
        evaluate_packet(client, body ? body + 4 : "{}");
    } else if (strcmp(path, "/api/rules") == 0 && strcmp(method, "POST") == 0) {
        char *body = strstr(request, "\r\n\r\n");
        body = body ? body + 4 : "{}";
        char name[64], protocol[12], action[8];
        get_string(body, "name", name, sizeof(name), "");
        get_string(body, "protocol", protocol, sizeof(protocol), "");
        get_string(body, "action", action, sizeof(action), "");
        int port = get_int(body, "port", -1);
        if (name[0] == '\0' || !valid_protocol(protocol, 1) ||
            (strcmp(action, "ALLOW") != 0 && strcmp(action, "BLOCK") != 0) ||
            port < 0 || port > 65535) {
            send_response(client, "400 Bad Request", "application/json",
                          "{\"error\":\"Invalid rule name, protocol, action, or port\"}");
            closesocket(client);
            return;
        }
        if (rule_count >= MAX_RULES) {
            send_response(client, "400 Bad Request", "application/json", "{\"error\":\"Rule limit reached\"}");
        } else {
            FirewallRule *r = &rules[rule_count++];
            r->id = next_id++;
            snprintf(r->name, sizeof(r->name), "%s", name);
            snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
            snprintf(r->action, sizeof(r->action), "%s", action);
            r->port = port;
            r->enabled = 1;
            char response[128];
            snprintf(response, sizeof(response), "{\"success\":true,\"id\":%d}", r->id);
            send_response(client, "201 Created", "application/json", response);
        }
    } else if (strncmp(path, "/api/rules/", 11) == 0 && strcmp(method, "DELETE") == 0) {
        errno = 0;
        char *end;
        long parsed_id = strtol(path + 11, &end, 10);
        if (end == path + 11 || *end != '\0' || errno == ERANGE || parsed_id < 1 || parsed_id > 2147483647L) {
            send_response(client, "400 Bad Request", "application/json", "{\"error\":\"Invalid rule ID\"}");
            closesocket(client);
            return;
        }
        int id = (int)parsed_id, found = 0;
        for (int i = 0; i < rule_count; i++) {
            if (rules[i].id == id) {
                for (int j = i; j < rule_count - 1; j++) rules[j] = rules[j + 1];
                rule_count--; found = 1; break;
            }
        }
        send_response(client, found ? "200 OK" : "404 Not Found", "application/json",
                      found ? "{\"success\":true}" : "{\"error\":\"Rule not found\"}");
    } else if ((strcmp(path, "/api/stats") == 0 || strcmp(path, "/api/rules") == 0 ||
                strcmp(path, "/api/evaluate") == 0 || strncmp(path, "/api/rules/", 11) == 0)) {
        send_response(client, "405 Method Not Allowed", "application/json",
                      "{\"error\":\"Method not allowed\"}");
    } else if (strcmp(method, "GET") == 0) {
        serve_static(client, path);
    } else {
        send_response(client, "405 Method Not Allowed", "application/json",
                      "{\"error\":\"Method not allowed\"}");
    }
    closesocket(client);
}

int main(void) {
    WSADATA wsa;
    SOCKET server, client;
    struct sockaddr_in address;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Winsock startup failed.\n"); return 1;
    }
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) { printf("Socket creation failed.\n"); WSACleanup(); return 1; }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(PORT);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        printf("Bind failed. Is port %d already in use?\n", PORT);
        closesocket(server); WSACleanup(); return 1;
    }
    if (listen(server, 10) == SOCKET_ERROR) {
        printf("Listen failed.\n");
        closesocket(server); WSACleanup(); return 1;
    }
    printf("\n============================================\n");
    printf("  FIREWALL RULES ENGINE - C BACKEND\n");
    printf("  Open http://localhost:%d in your browser\n", PORT);
    printf("  API server running at http://localhost:%d\n", PORT);
    printf("  Press Ctrl+C to stop\n");
    printf("============================================\n\n");
    while ((client = accept(server, NULL, NULL)) != INVALID_SOCKET) handle_client(client);
    closesocket(server);
    WSACleanup();
    return 0;
}
