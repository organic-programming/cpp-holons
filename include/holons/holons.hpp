#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <condition_variable>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#if defined(_MSC_VER) && !defined(_SSIZE_T_DEFINED)
using ssize_t = intptr_t;
#define _SSIZE_T_DEFINED
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
#if __has_include(<nlohmann/json.hpp>)
#include <nlohmann/json.hpp>
#elif __has_include("/opt/homebrew/include/nlohmann/json.hpp")
#include "/opt/homebrew/include/nlohmann/json.hpp"
#elif __has_include("/usr/local/include/nlohmann/json.hpp")
#include "/usr/local/include/nlohmann/json.hpp"
#else
#error "nlohmann/json.hpp is required for holon_rpc_client"
#endif
#include <random>
#include <sstream>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <optional>
#include <unordered_map>
#include <variant>
#include <vector>

namespace holons {

#ifdef _WIN32
namespace detail {
struct winsock_init {
  winsock_init() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
  }

  ~winsock_init() { WSACleanup(); }
};

inline void ensure_winsock() {
  static winsock_init instance;
  (void)instance;
}
} // namespace detail
#endif

inline int close_fd(int fd, bool is_socket) {
#ifdef _WIN32
  return is_socket ? static_cast<int>(::closesocket(static_cast<SOCKET>(fd)))
                   : ::_close(fd);
#else
  (void)is_socket;
  return ::close(fd);
#endif
}

inline int unlink_path(const char *path) {
#ifdef _WIN32
  return ::_unlink(path);
#else
  return ::unlink(path);
#endif
}

inline int socket_shutdown_both() {
#ifdef _WIN32
  return SD_BOTH;
#else
  return SHUT_RDWR;
#endif
}

inline std::string last_socket_error() {
#ifdef _WIN32
  return "winsock error " + std::to_string(WSAGetLastError());
#else
  return std::strerror(errno);
#endif
}

#ifdef _WIN32
inline int win_socketpair(int fds[2]) {
  fds[0] = -1;
  fds[1] = -1;

  SOCKET listener = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listener == INVALID_SOCKET) {
    return -1;
  }

  int one = 1;
  ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&one), sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (::bind(listener, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
      0) {
    ::closesocket(listener);
    return -1;
  }

  int addrlen = sizeof(addr);
  if (::getsockname(listener, reinterpret_cast<sockaddr *>(&addr), &addrlen) !=
      0) {
    ::closesocket(listener);
    return -1;
  }

  if (::listen(listener, 1) != 0) {
    ::closesocket(listener);
    return -1;
  }

  SOCKET client = ::socket(AF_INET, SOCK_STREAM, 0);
  if (client == INVALID_SOCKET) {
    ::closesocket(listener);
    return -1;
  }

  if (::connect(client, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
      0) {
    ::closesocket(client);
    ::closesocket(listener);
    return -1;
  }

  SOCKET server = ::accept(listener, nullptr, nullptr);
  ::closesocket(listener);
  if (server == INVALID_SOCKET) {
    ::closesocket(client);
    return -1;
  }

  fds[0] = static_cast<int>(server);
  fds[1] = static_cast<int>(client);
  return 0;
}
#endif

/// Default transport URI when --listen is omitted.
constexpr std::string_view kDefaultURI = "tcp://:9090";

/// Extract the scheme from a transport URI.
inline std::string scheme(std::string_view uri) {
  auto pos = uri.find("://");
  return pos != std::string_view::npos ? std::string(uri.substr(0, pos))
                                       : std::string(uri);
}

/// Parse --listen or --port from command-line args.
inline std::string parse_flags(const std::vector<std::string> &args) {
  for (size_t i = 0; i < args.size(); ++i) {
    if (args[i] == "--listen" && i + 1 < args.size())
      return args[i + 1];
    if (args[i] == "--port" && i + 1 < args.size())
      return "tcp://:" + args[i + 1];
  }
  return std::string(kDefaultURI);
}

/// Parsed transport URI.
struct parsed_uri {
  std::string raw;
  std::string scheme;
  std::string host;
  int port = 0;
  std::string path;
  bool secure = false;
};

struct tcp_listener {
  int fd = -1;
  std::string host;
  int port = 0;
};

struct unix_listener {
  int fd = -1;
  std::string path;
};

struct stdio_listener {
  std::string address = "stdio://";
  bool consumed = false;
};

struct mem_listener {
  std::string address = "mem://";
  int server_fd = -1;
  int client_fd = -1;
  bool server_consumed = false;
  bool client_consumed = false;
};

struct ws_listener {
  std::string host;
  int port = 0;
  std::string path;
  bool secure = false;
};

using listener =
    std::variant<tcp_listener, unix_listener, stdio_listener, mem_listener,
                 ws_listener>;

struct connection {
  int read_fd = -1;
  int write_fd = -1;
  std::string scheme;
  bool owns_read_fd = true;
  bool owns_write_fd = true;
};

inline std::tuple<std::string, int> split_host_port(const std::string &addr,
                                                     int default_port) {
  if (addr.empty())
    return {"0.0.0.0", default_port};

  auto pos = addr.rfind(':');
  if (pos == std::string::npos)
    return {addr, default_port};

  std::string host = addr.substr(0, pos);
  if (host.empty())
    host = "0.0.0.0";
  std::string port_text = addr.substr(pos + 1);
  int port = port_text.empty() ? default_port : std::stoi(port_text);
  return {host, port};
}

inline parsed_uri parse_uri(const std::string &uri) {
  std::string s = scheme(uri);

  if (s == "tcp") {
    if (uri.rfind("tcp://", 0) != 0)
      throw std::invalid_argument("invalid tcp URI: " + uri);
    auto [host, port] = split_host_port(uri.substr(6), 9090);
    return {uri, "tcp", host, port, "", false};
  }

  if (s == "unix") {
    if (uri.rfind("unix://", 0) != 0)
      throw std::invalid_argument("invalid unix URI: " + uri);
    auto path = uri.substr(7);
    if (path.empty())
      throw std::invalid_argument("invalid unix URI: " + uri);
    return {uri, "unix", "", 0, path, false};
  }

  if (s == "stdio") {
    return {"stdio://", "stdio", "", 0, "", false};
  }

  if (s == "mem") {
    std::string raw = uri.rfind("mem://", 0) == 0 ? uri : "mem://";
    std::string name = raw.size() > 6 ? raw.substr(6) : "";
    return {raw, "mem", "", 0, name, false};
  }

  if (s == "ws" || s == "wss") {
    bool secure = s == "wss";
    std::string prefix = secure ? "wss://" : "ws://";
    if (uri.rfind(prefix, 0) != 0)
      throw std::invalid_argument("invalid ws URI: " + uri);

    std::string trimmed = uri.substr(prefix.size());
    auto slash = trimmed.find('/');
    std::string addr = slash == std::string::npos ? trimmed : trimmed.substr(0, slash);
    std::string path = slash == std::string::npos ? "/grpc" : trimmed.substr(slash);
    if (path.empty())
      path = "/grpc";

    auto [host, port] = split_host_port(addr, secure ? 443 : 80);
    return {uri, s, host, port, path, secure};
  }

  throw std::invalid_argument("unsupported transport URI: " + uri);
}

inline listener listen(const std::string &uri) {
#ifdef _WIN32
  detail::ensure_winsock();
#endif
  auto parsed = parse_uri(uri);

  if (parsed.scheme == "tcp") {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
      throw std::runtime_error("socket() failed");

    int one = 1;
#ifdef _WIN32
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char *>(&one), sizeof(one));
#else
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(parsed.port));
    if (parsed.host == "0.0.0.0") {
      addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, parsed.host.c_str(), &addr.sin_addr) != 1) {
      close_fd(fd, true);
      throw std::runtime_error("invalid tcp host: " + parsed.host);
    }

    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
      close_fd(fd, true);
      throw std::runtime_error("bind() failed");
    }
    if (::listen(fd, 16) < 0) {
      close_fd(fd, true);
      throw std::runtime_error("listen() failed");
    }
    return tcp_listener{fd, parsed.host, parsed.port};
  }

  if (parsed.scheme == "unix") {
#ifdef _WIN32
    throw std::runtime_error("unix:// not supported on Windows");
#else
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
      throw std::runtime_error("socket() failed");

    unlink_path(parsed.path.c_str());
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", parsed.path.c_str());

    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
      close_fd(fd, true);
      throw std::runtime_error("bind(unix) failed");
    }
    if (::listen(fd, 16) < 0) {
      close_fd(fd, true);
      throw std::runtime_error("listen(unix) failed");
    }
    return unix_listener{fd, parsed.path};
#endif
  }

  if (parsed.scheme == "stdio")
    return stdio_listener{parsed.raw, false};
  if (parsed.scheme == "mem") {
    int fds[2] = {-1, -1};
#ifdef _WIN32
    if (win_socketpair(fds) != 0) {
#else
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
#endif
      throw std::runtime_error("mem socketpair() failed");
    }
    return mem_listener{parsed.raw, fds[0], fds[1], false, false};
  }
  if (parsed.scheme == "ws" || parsed.scheme == "wss")
    return ws_listener{parsed.host, parsed.port, parsed.path, parsed.secure};

  throw std::invalid_argument("unsupported transport URI: " + uri);
}

/// Accept one connection from a listener.
/// - tcp/unix: OS socket accept
/// - stdio: single connection over stdin/stdout
/// - mem: server side of in-process pair
inline connection accept(listener &lis) {
  if (auto *tcp = std::get_if<tcp_listener>(&lis)) {
    int fd = ::accept(tcp->fd, nullptr, nullptr);
    if (fd < 0) {
      throw std::runtime_error("accept(tcp) failed: " + last_socket_error());
    }
    return connection{fd, fd, "tcp", true, true};
  }

  if (auto *unix_lis = std::get_if<unix_listener>(&lis)) {
    int fd = ::accept(unix_lis->fd, nullptr, nullptr);
    if (fd < 0) {
      throw std::runtime_error("accept(unix) failed: " + last_socket_error());
    }
    return connection{fd, fd, "unix", true, true};
  }

  if (auto *stdio = std::get_if<stdio_listener>(&lis)) {
    if (stdio->consumed) {
      throw std::runtime_error("stdio:// accepts exactly one connection");
    }
    stdio->consumed = true;
    return connection{STDIN_FILENO, STDOUT_FILENO, "stdio", false, false};
  }

  if (auto *mem = std::get_if<mem_listener>(&lis)) {
    if (mem->server_consumed || mem->server_fd < 0) {
      throw std::runtime_error("mem:// server side already consumed");
    }
    mem->server_consumed = true;
    int fd = mem->server_fd;
    mem->server_fd = -1;
    return connection{fd, fd, "mem", true, true};
  }

  if (std::holds_alternative<ws_listener>(lis)) {
    throw std::runtime_error(
        "ws/wss runtime accept is unsupported (metadata-only listener)");
  }

  throw std::runtime_error("listener variant cannot accept");
}

/// Dial the client side of a mem:// listener.
inline connection mem_dial(listener &lis) {
  auto *mem = std::get_if<mem_listener>(&lis);
  if (mem == nullptr) {
    throw std::invalid_argument("mem_dial() requires mem:// listener");
  }
  if (mem->client_consumed || mem->client_fd < 0) {
    throw std::runtime_error("mem:// client side already consumed");
  }
  mem->client_consumed = true;
  int fd = mem->client_fd;
  mem->client_fd = -1;
  return connection{fd, fd, "mem", true, true};
}

inline ssize_t conn_read(const connection &conn, void *buf, size_t n) {
  if (conn.scheme == "stdio") {
#ifdef _WIN32
    return ::_read(conn.read_fd, buf, static_cast<unsigned int>(n));
#else
    return ::read(conn.read_fd, buf, n);
#endif
  }
#ifdef _WIN32
  return ::recv(static_cast<SOCKET>(conn.read_fd), static_cast<char *>(buf),
                static_cast<int>(n), 0);
#else
  return ::recv(conn.read_fd, static_cast<char *>(buf), n, 0);
#endif
}

inline ssize_t conn_write(const connection &conn, const void *buf, size_t n) {
  if (conn.scheme == "stdio") {
#ifdef _WIN32
    return ::_write(conn.write_fd, buf, static_cast<unsigned int>(n));
#else
    return ::write(conn.write_fd, buf, n);
#endif
  }
#ifdef _WIN32
  return ::send(static_cast<SOCKET>(conn.write_fd),
                static_cast<const char *>(buf), static_cast<int>(n), 0);
#else
  return ::send(conn.write_fd, static_cast<const char *>(buf), n, 0);
#endif
}

inline void close_connection(connection &conn) {
  const int read_fd = conn.read_fd;
  const int write_fd = conn.write_fd;
  const bool socket_fds = conn.scheme != "stdio";

  if (conn.owns_read_fd && read_fd >= 0) {
    close_fd(read_fd, socket_fds);
  }
  if (conn.owns_write_fd && write_fd >= 0 && write_fd != read_fd) {
    close_fd(write_fd, socket_fds);
  }

  conn.read_fd = -1;
  conn.write_fd = -1;
}

inline void close_listener(listener &lis) {
  if (auto *tcp = std::get_if<tcp_listener>(&lis)) {
    if (tcp->fd >= 0) {
      close_fd(tcp->fd, true);
      tcp->fd = -1;
    }
    return;
  }
  if (auto *unix_lis = std::get_if<unix_listener>(&lis)) {
    if (unix_lis->fd >= 0) {
      close_fd(unix_lis->fd, true);
      unix_lis->fd = -1;
    }
    if (!unix_lis->path.empty())
      unlink_path(unix_lis->path.c_str());
    return;
  }
  if (auto *mem = std::get_if<mem_listener>(&lis)) {
    if (mem->server_fd >= 0) {
      close_fd(mem->server_fd, true);
      mem->server_fd = -1;
    }
    if (mem->client_fd >= 0) {
      close_fd(mem->client_fd, true);
      mem->client_fd = -1;
    }
  }
}

class holon_rpc_error : public std::runtime_error {
public:
  holon_rpc_error(int code, const std::string &message,
                  nlohmann::json data = nullptr)
      : std::runtime_error("rpc error " + std::to_string(code) + ": " +
                           message),
        code_(code), data_(std::move(data)) {}

  int code() const { return code_; }
  const nlohmann::json &data() const { return data_; }

private:
  int code_;
  nlohmann::json data_;
};

class holon_rpc_client {
public:
  using json = nlohmann::json;
  using handler_fn = std::function<json(const json &)>;

  holon_rpc_client(int heartbeat_interval_ms = 15000,
                   int heartbeat_timeout_ms = 5000,
                   int reconnect_min_delay_ms = 500,
                   int reconnect_max_delay_ms = 30000,
                   double reconnect_factor = 2.0,
                   double reconnect_jitter = 0.1,
                   int connect_timeout_ms = 10000,
                   int request_timeout_ms = 10000)
      : heartbeat_interval_ms_(heartbeat_interval_ms),
        heartbeat_timeout_ms_(heartbeat_timeout_ms),
        reconnect_min_delay_ms_(reconnect_min_delay_ms),
        reconnect_max_delay_ms_(reconnect_max_delay_ms),
        reconnect_factor_(reconnect_factor),
        reconnect_jitter_(reconnect_jitter),
        connect_timeout_ms_(connect_timeout_ms),
        request_timeout_ms_(request_timeout_ms) {}

  ~holon_rpc_client() { close(); }

  void connect(const std::string &url) {
    if (url.empty()) {
      throw std::invalid_argument("url is required");
    }

    close();

    endpoint_ = url;
    next_id_.store(0);
    reconnect_attempt_ = 0;
    running_.store(true);
    closed_.store(false);
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      connected_ = false;
      last_error_.clear();
    }

    io_thread_ = std::thread([this]() { io_loop(); });
    heartbeat_thread_ = std::thread([this]() { heartbeat_loop(); });

    std::unique_lock<std::mutex> lock(state_mu_);
    bool ready = connected_cv_.wait_for(
        lock, std::chrono::milliseconds(connect_timeout_ms_),
        [this]() { return connected_ || !running_.load(); });

    if (!ready || !connected_) {
      std::string error =
          last_error_.empty() ? "holon-rpc connect timeout" : last_error_;
      lock.unlock();
      close();
      throw std::runtime_error(error);
    }
  }

  void register_handler(const std::string &method, handler_fn handler) {
    if (method.empty()) {
      throw std::invalid_argument("method is required");
    }
    std::lock_guard<std::mutex> lock(handlers_mu_);
    handlers_[method] = std::move(handler);
  }

  json invoke(const std::string &method, const json &params = json::object(),
              int timeout_ms = -1) {
    if (method.empty()) {
      throw std::invalid_argument("method is required");
    }

    wait_connected(connect_timeout_ms_);

    auto id = std::string("c") + std::to_string(next_id_.fetch_add(1) + 1);
    auto call = std::make_shared<pending_call>();
    {
      std::lock_guard<std::mutex> lock(pending_mu_);
      pending_[id] = call;
    }

    json payload = {{"jsonrpc", "2.0"}, {"id", id}, {"method", method},
                    {"params", params.is_object() ? params : json::object()}};

    try {
      send_json(payload);
    } catch (...) {
      remove_pending(id);
      throw;
    }

    int timeout = timeout_ms > 0 ? timeout_ms : request_timeout_ms_;
    std::unique_lock<std::mutex> lock(call->mu);
    bool done = call->cv.wait_for(lock, std::chrono::milliseconds(timeout),
                                  [&call]() { return call->done; });
    if (!done) {
      remove_pending(id);
      throw std::runtime_error("invoke timeout");
    }
    if (call->has_error) {
      throw holon_rpc_error(call->code, call->message, call->data);
    }
    return call->result;
  }

  void close() {
    if (!running_.load() && closed_.load()) {
      return;
    }

    closed_.store(true);
    running_.store(false);
    force_disconnect();

    {
      std::lock_guard<std::mutex> lock(state_mu_);
      connected_ = false;
    }
    connected_cv_.notify_all();

    if (io_thread_.joinable()) {
      io_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
      heartbeat_thread_.join();
    }

    close_socket();
    fail_all_pending(-32000, "holon-rpc client closed");
  }

private:
  struct pending_call {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    bool has_error = false;
    int code = -32603;
    std::string message = "internal error";
    json data = nullptr;
    json result = json::object();
  };

  void io_loop() {
    while (running_.load()) {
      if (socket_fd() < 0) {
        try {
          if (!open_socket()) {
            if (!running_.load()) {
              return;
            }
            auto delay = compute_backoff_delay_ms(reconnect_attempt_++);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
          }
        } catch (const std::exception &e) {
          {
            std::lock_guard<std::mutex> lock(state_mu_);
            connected_ = false;
            last_error_ = e.what();
          }
          connected_cv_.notify_all();
          running_.store(false);
          closed_.store(true);
          fail_all_pending(-32000, e.what());
          return;
        }

        reconnect_attempt_ = 0;
        {
          std::lock_guard<std::mutex> lock(state_mu_);
          connected_ = true;
          last_error_.clear();
        }
        connected_cv_.notify_all();
      }

      std::string text;
      if (!read_text_frame(text)) {
        mark_disconnected("holon-rpc connection closed");
        continue;
      }

      handle_incoming(text);
    }
  }

  void heartbeat_loop() {
    while (running_.load()) {
      sleep_interruptible(heartbeat_interval_ms_);
      if (!running_.load()) {
        return;
      }
      if (!is_connected()) {
        continue;
      }

      try {
        (void)invoke("rpc.heartbeat", json::object(), heartbeat_timeout_ms_);
      } catch (...) {
        force_disconnect();
      }
    }
  }

  void sleep_interruptible(int duration_ms) const {
    int slept = 0;
    while (running_.load() && slept < duration_ms) {
      int step = std::min(100, duration_ms - slept);
      std::this_thread::sleep_for(std::chrono::milliseconds(step));
      slept += step;
    }
  }

  void wait_connected(int timeout_ms) {
    std::unique_lock<std::mutex> lock(state_mu_);
    bool ready = connected_cv_.wait_for(
        lock, std::chrono::milliseconds(timeout_ms),
        [this]() { return connected_ || !running_.load(); });
    if (!ready || !connected_) {
      throw std::runtime_error(last_error_.empty() ? "not connected"
                                                   : last_error_);
    }
  }

  bool is_connected() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return connected_;
  }

  int socket_fd() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return sockfd_;
  }

  void set_socket_fd(int fd) {
    std::lock_guard<std::mutex> lock(state_mu_);
    sockfd_ = fd;
  }

  void close_socket() {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (sockfd_ >= 0) {
      close_fd(sockfd_, true);
      sockfd_ = -1;
    }
  }

  void force_disconnect() {
    int fd = -1;
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      fd = sockfd_;
    }
    if (fd >= 0) {
      ::shutdown(fd, socket_shutdown_both());
    }
  }

  void mark_disconnected(const std::string &reason) {
    close_socket();
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      connected_ = false;
      last_error_ = reason;
    }
    connected_cv_.notify_all();
    fail_all_pending(-32000, reason);
  }

  static bool send_all(int fd, const void *data, size_t size) {
    const auto *ptr = static_cast<const uint8_t *>(data);
    size_t sent = 0;
    while (sent < size) {
      size_t chunk = std::min(size - sent,
                              static_cast<size_t>(std::numeric_limits<int>::max()));
      ssize_t n = ::send(fd, reinterpret_cast<const char *>(ptr + sent),
                         static_cast<int>(chunk), 0);
      if (n <= 0) {
        return false;
      }
      sent += static_cast<size_t>(n);
    }
    return true;
  }

  static bool read_exact(int fd, void *data, size_t size) {
    auto *ptr = static_cast<uint8_t *>(data);
    size_t got = 0;
    while (got < size) {
      size_t chunk = std::min(size - got,
                              static_cast<size_t>(std::numeric_limits<int>::max()));
      ssize_t n = ::recv(fd, reinterpret_cast<char *>(ptr + got),
                         static_cast<int>(chunk), 0);
      if (n <= 0) {
        return false;
      }
      got += static_cast<size_t>(n);
    }
    return true;
  }

  bool open_socket() {
#ifdef _WIN32
    detail::ensure_winsock();
#endif
    auto parsed = parse_uri(endpoint_);
    if (parsed.scheme != "ws" && parsed.scheme != "wss") {
      throw std::runtime_error("holon-rpc requires ws:// or wss:// endpoint");
    }
    if (parsed.secure) {
      throw std::runtime_error(
          "wss:// is not supported in cpp-holons without TLS dependencies");
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(parsed.port));
    if (::inet_pton(AF_INET, parsed.host.c_str(), &addr.sin_addr) != 1) {
      close_fd(fd, true);
      throw std::runtime_error("invalid ws host: " + parsed.host);
    }

    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
      close_fd(fd, true);
      return false;
    }

    std::ostringstream req;
    req << "GET " << (parsed.path.empty() ? "/rpc" : parsed.path)
        << " HTTP/1.1\r\n";
    req << "Host: " << parsed.host << ":" << parsed.port << "\r\n";
    req << "Upgrade: websocket\r\n";
    req << "Connection: Upgrade\r\n";
    req << "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    req << "Sec-WebSocket-Version: 13\r\n";
    req << "Sec-WebSocket-Protocol: holon-rpc\r\n\r\n";

    auto req_str = req.str();
    if (!send_all(fd, req_str.data(), req_str.size())) {
      close_fd(fd, true);
      return false;
    }

    std::string headers;
    headers.reserve(4096);
    char ch = 0;
    while (headers.find("\r\n\r\n") == std::string::npos) {
      ssize_t n = ::recv(fd, &ch, 1, 0);
      if (n <= 0) {
        close_fd(fd, true);
        return false;
      }
      headers.push_back(ch);
      if (headers.size() > 16384) {
        close_fd(fd, true);
        throw std::runtime_error("websocket handshake too large");
      }
    }

    std::string lower = headers;
    for (auto &c : lower) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (lower.find(" 101 ") == std::string::npos ||
        lower.find("sec-websocket-protocol: holon-rpc") ==
            std::string::npos) {
      close_fd(fd, true);
      throw std::runtime_error(
          "server did not negotiate holon-rpc websocket protocol");
    }

    set_socket_fd(fd);
    return true;
  }

  void send_json(const json &payload) {
    std::string data = payload.dump();
    if (!send_frame(0x1, data)) {
      throw std::runtime_error("websocket send failed");
    }
  }

  bool send_frame(uint8_t opcode, const std::string &payload) {
    int fd = socket_fd();
    if (fd < 0) {
      return false;
    }

    std::vector<uint8_t> frame;
    frame.reserve(payload.size() + 16);
    frame.push_back(static_cast<uint8_t>(0x80 | (opcode & 0x0F)));

    uint64_t len = payload.size();
    if (len < 126) {
      frame.push_back(static_cast<uint8_t>(0x80 | len));
    } else if (len <= 0xFFFF) {
      frame.push_back(static_cast<uint8_t>(0x80 | 126));
      frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
      frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
      frame.push_back(static_cast<uint8_t>(0x80 | 127));
      for (int i = 7; i >= 0; --i) {
        frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
      }
    }

    std::array<uint8_t, 4> mask{};
    for (auto &b : mask) {
      b = static_cast<uint8_t>(random_device_());
      frame.push_back(b);
    }

    for (size_t i = 0; i < payload.size(); ++i) {
      frame.push_back(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
    }

    std::lock_guard<std::mutex> lock(send_mu_);
    return send_all(fd, frame.data(), frame.size());
  }

  bool read_text_frame(std::string &out) {
    out.clear();
    std::string fragmented;
    bool reading_fragment = false;

    while (running_.load()) {
      int fd = socket_fd();
      if (fd < 0) {
        return false;
      }

      uint8_t header[2];
      if (!read_exact(fd, header, 2)) {
        return false;
      }

      bool fin = (header[0] & 0x80) != 0;
      uint8_t opcode = static_cast<uint8_t>(header[0] & 0x0F);
      bool masked = (header[1] & 0x80) != 0;
      uint64_t len = static_cast<uint64_t>(header[1] & 0x7F);

      if (len == 126) {
        uint8_t ext[2];
        if (!read_exact(fd, ext, 2)) {
          return false;
        }
        len = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
      } else if (len == 127) {
        uint8_t ext[8];
        if (!read_exact(fd, ext, 8)) {
          return false;
        }
        len = 0;
        for (int i = 0; i < 8; ++i) {
          len = (len << 8) | ext[i];
        }
      }

      std::array<uint8_t, 4> mask{};
      if (masked) {
        if (!read_exact(fd, mask.data(), mask.size())) {
          return false;
        }
      }

      std::string payload(len, '\0');
      if (len > 0 && !read_exact(fd, payload.data(), len)) {
        return false;
      }
      if (masked) {
        for (size_t i = 0; i < payload.size(); ++i) {
          payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
        }
      }

      if (opcode == 0x8) { // close
        return false;
      }
      if (opcode == 0x9) { // ping
        if (!send_frame(0xA, payload)) {
          return false;
        }
        continue;
      }
      if (opcode == 0xA) { // pong
        continue;
      }

      if (opcode == 0x1 || opcode == 0x0) { // text or continuation
        if (opcode == 0x1 && !reading_fragment) {
          fragmented.clear();
        }
        fragmented.append(payload);
        reading_fragment = !fin;
        if (fin) {
          out = fragmented;
          return true;
        }
        continue;
      }
    }

    return false;
  }

  void handle_incoming(const std::string &text) {
    json msg;
    try {
      msg = json::parse(text);
    } catch (...) {
      return;
    }

    if (!msg.is_object()) {
      return;
    }

    if (msg.contains("method")) {
      handle_request(msg);
      return;
    }
    if (msg.contains("result") || msg.contains("error")) {
      handle_response(msg);
    }
  }

  void handle_request(const json &msg) {
    json id = msg.contains("id") ? msg["id"] : json();
    bool has_id = !id.is_null();

    std::string method;
    if (msg.contains("method") && msg["method"].is_string()) {
      method = msg["method"].get<std::string>();
    }
    std::string jsonrpc;
    if (msg.contains("jsonrpc") && msg["jsonrpc"].is_string()) {
      jsonrpc = msg["jsonrpc"].get<std::string>();
    }

    if (jsonrpc != "2.0" || method.empty()) {
      if (has_id) {
        send_error(id, -32600, "invalid request");
      }
      return;
    }

    if (method == "rpc.heartbeat") {
      if (has_id) {
        send_result(id, json::object());
      }
      return;
    }

    if (has_id) {
      if (!id.is_string()) {
        send_error(id, -32600, "server request id must start with 's'");
        return;
      }
      auto sid = id.get<std::string>();
      if (sid.empty() || sid[0] != 's') {
        send_error(id, -32600, "server request id must start with 's'");
        return;
      }
    }

    handler_fn handler;
    {
      std::lock_guard<std::mutex> lock(handlers_mu_);
      auto it = handlers_.find(method);
      if (it == handlers_.end()) {
        if (has_id) {
          send_error(id, -32601, "method \"" + method + "\" not found");
        }
        return;
      }
      handler = it->second;
    }

    json params = msg.contains("params") && msg["params"].is_object()
                      ? msg["params"]
                      : json::object();

    try {
      json result = handler(params);
      if (has_id) {
        send_result(id, result.is_object() ? result : json::object());
      }
    } catch (const holon_rpc_error &rpc_error) {
      if (has_id) {
        send_error(id, rpc_error.code(), rpc_error.what(), rpc_error.data());
      }
    } catch (const std::exception &e) {
      if (has_id) {
        send_error(id, 13, e.what());
      }
    } catch (...) {
      if (has_id) {
        send_error(id, 13, "internal error");
      }
    }
  }

  void handle_response(const json &msg) {
    if (!msg.contains("id")) {
      return;
    }

    std::string id;
    if (msg["id"].is_string()) {
      id = msg["id"].get<std::string>();
    } else {
      id = msg["id"].dump();
    }

    std::shared_ptr<pending_call> call;
    {
      std::lock_guard<std::mutex> lock(pending_mu_);
      auto it = pending_.find(id);
      if (it == pending_.end()) {
        return;
      }
      call = it->second;
      pending_.erase(it);
    }

    std::lock_guard<std::mutex> lock(call->mu);
    if (msg.contains("error") && msg["error"].is_object()) {
      const auto &err = msg["error"];
      call->has_error = true;
      call->code = err.contains("code") && err["code"].is_number_integer()
                       ? err["code"].get<int>()
                       : -32603;
      call->message = err.contains("message") && err["message"].is_string()
                          ? err["message"].get<std::string>()
                          : "internal error";
      call->data = err.contains("data") ? err["data"] : nullptr;
    } else {
      call->result = msg.contains("result") && msg["result"].is_object()
                         ? msg["result"]
                         : json::object();
    }
    call->done = true;
    call->cv.notify_all();
  }

  void send_result(const json &id, const json &result) {
    json payload = {{"jsonrpc", "2.0"}, {"id", id},
                    {"result", result.is_object() ? result : json::object()}};
    send_json(payload);
  }

  void send_error(const json &id, int code, const std::string &message,
                  const json &data = nullptr) {
    json err = {{"code", code}, {"message", message}};
    if (!data.is_null()) {
      err["data"] = data;
    }
    json payload = {{"jsonrpc", "2.0"}, {"id", id}, {"error", err}};
    send_json(payload);
  }

  void fail_all_pending(int code, const std::string &message) {
    std::unordered_map<std::string, std::shared_ptr<pending_call>> snapshot;
    {
      std::lock_guard<std::mutex> lock(pending_mu_);
      snapshot.swap(pending_);
    }

    for (auto &kv : snapshot) {
      auto &call = kv.second;
      std::lock_guard<std::mutex> lock(call->mu);
      call->done = true;
      call->has_error = true;
      call->code = code;
      call->message = message;
      call->data = nullptr;
      call->cv.notify_all();
    }
  }

  void remove_pending(const std::string &id) {
    std::lock_guard<std::mutex> lock(pending_mu_);
    pending_.erase(id);
  }

  int compute_backoff_delay_ms(int attempt) const {
    double base = std::min(
        reconnect_min_delay_ms_ * std::pow(reconnect_factor_, attempt),
        static_cast<double>(reconnect_max_delay_ms_));
    double jitter = base * reconnect_jitter_ *
                    std::uniform_real_distribution<double>(0.0, 1.0)(
                        mutable_rng_);
    int delay = static_cast<int>(base + jitter);
    return std::max(1, delay);
  }

  int heartbeat_interval_ms_;
  int heartbeat_timeout_ms_;
  int reconnect_min_delay_ms_;
  int reconnect_max_delay_ms_;
  double reconnect_factor_;
  double reconnect_jitter_;
  int connect_timeout_ms_;
  int request_timeout_ms_;

  mutable std::mutex state_mu_;
  mutable std::condition_variable connected_cv_;
  int sockfd_ = -1;
  bool connected_ = false;
  std::string last_error_;

  std::string endpoint_;
  std::atomic<bool> running_{false};
  std::atomic<bool> closed_{true};
  std::thread io_thread_;
  std::thread heartbeat_thread_;
  int reconnect_attempt_ = 0;

  std::mutex send_mu_;
  mutable std::mt19937 mutable_rng_{std::random_device{}()};
  std::random_device random_device_;

  std::mutex handlers_mu_;
  std::unordered_map<std::string, handler_fn> handlers_;

  std::mutex pending_mu_;
  std::unordered_map<std::string, std::shared_ptr<pending_call>> pending_;

  std::atomic<uint64_t> next_id_{0};
};

/// Parsed holon identity from a holon manifest.
struct HolonIdentity {
  std::string uuid;
  std::string given_name;
  std::string family_name;
  std::string motto;
  std::string composer;
  std::string clade;
  std::string status;
  std::string born;
  std::string lang;
};

struct HolonBuild {
  std::string runner;
  std::string main;
};

struct HolonArtifacts {
  std::string binary;
  std::string primary;
};

struct HolonManifest {
  std::string kind;
  HolonBuild build;
  HolonArtifacts artifacts;
};

struct HolonEntry {
  std::string slug;
  std::string uuid;
  std::filesystem::path dir;
  std::filesystem::path relative_path;
  std::string origin;
  HolonIdentity identity;
  std::optional<HolonManifest> manifest;
};

inline std::string trim_copy(std::string value) {
  auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

inline std::string strip_quotes(std::string value) {
  if (value.size() >= 2 &&
      ((value.front() == '"' && value.back() == '"') ||
       (value.front() == '\'' && value.back() == '\''))) {
    return value.substr(1, value.size() - 2);
  }
  return value;
}

/// Extract a YAML value from a simple key: "value" line.
/// Handles both quoted and unquoted values.
inline std::string yaml_value(const std::string &line) {
  auto colon = line.find(':');
  if (colon == std::string::npos)
    return "";
  return strip_quotes(trim_copy(line.substr(colon + 1)));
}

inline std::string slug_from_identity(const HolonIdentity &id) {
  auto append_part = [](std::string *out, const std::string &value) {
    auto trimmed = trim_copy(value);
    for (char ch : trimmed) {
      if (ch == '?') {
        continue;
      }
      if (std::isspace(static_cast<unsigned char>(ch))) {
        out->push_back('-');
      } else {
        out->push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
      }
    }
    while (!out->empty() && out->back() == '-') {
      out->pop_back();
    }
  };

  std::string slug;
  append_part(&slug, id.given_name);
  if (!slug.empty() && (!id.family_name.empty())) {
    slug.push_back('-');
  }
  append_part(&slug, id.family_name);
  while (!slug.empty() && slug.back() == '-') {
    slug.pop_back();
  }
  return slug;
}

inline std::optional<HolonManifest> parse_manifest(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("cannot open: " + path);
  }

  HolonManifest manifest;
  bool saw_mapping = false;
  bool saw_manifest_value = false;
  std::string section;
  std::string line;

  while (std::getline(file, line)) {
    auto indent = line.find_first_not_of(" \t");
    if (indent == std::string::npos) {
      continue;
    }

    std::string trimmed = trim_copy(line);
    if (trimmed.empty() || trimmed.front() == '#') {
      continue;
    }

    auto colon = trimmed.find(':');
    if (colon == std::string::npos) {
      continue;
    }

    saw_mapping = true;
    std::string key = trimmed.substr(0, colon);
    std::string value = yaml_value(trimmed);

    if (indent == 0) {
      section.clear();
      if (key == "kind") {
        manifest.kind = value;
        saw_manifest_value = true;
      } else if ((key == "build" || key == "artifacts") && value.empty()) {
        section = key;
      }
      continue;
    }

    if (section == "build") {
      if (key == "runner") {
        manifest.build.runner = value;
        saw_manifest_value = true;
      } else if (key == "main") {
        manifest.build.main = value;
        saw_manifest_value = true;
      }
    } else if (section == "artifacts") {
      if (key == "binary") {
        manifest.artifacts.binary = value;
        saw_manifest_value = true;
      } else if (key == "primary") {
        manifest.artifacts.primary = value;
        saw_manifest_value = true;
      }
    }
  }

  if (!saw_mapping) {
    throw std::runtime_error(path + ": holon.yaml must be a YAML mapping");
  }
  if (!saw_manifest_value) {
    return std::nullopt;
  }
  return manifest;
}

/// Parse a holon.yaml file.
inline HolonIdentity parse_holon(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open())
    throw std::runtime_error("cannot open: " + path);

  std::string text((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());

  HolonIdentity id;
  bool saw_mapping = false;

  // Simple line-by-line parsing
  std::istringstream ss(text);
  std::string line;
  while (std::getline(ss, line)) {
    std::string trimmed = trim_copy(line);
    if (trimmed.empty() || trimmed.front() == '#') {
      continue;
    }
    if (trimmed.find(':') != std::string::npos)
      saw_mapping = true;
    if (trimmed.find("uuid:") == 0)
      id.uuid = yaml_value(trimmed);
    else if (trimmed.find("given_name:") == 0)
      id.given_name = yaml_value(trimmed);
    else if (trimmed.find("family_name:") == 0)
      id.family_name = yaml_value(trimmed);
    else if (trimmed.find("motto:") == 0)
      id.motto = yaml_value(trimmed);
    else if (trimmed.find("composer:") == 0)
      id.composer = yaml_value(trimmed);
    else if (trimmed.find("clade:") == 0)
      id.clade = yaml_value(trimmed);
    else if (trimmed.find("status:") == 0)
      id.status = yaml_value(trimmed);
    else if (trimmed.find("born:") == 0)
      id.born = yaml_value(trimmed);
    else if (trimmed.find("lang:") == 0)
      id.lang = yaml_value(trimmed);
  }
  if (!saw_mapping)
    throw std::runtime_error(path + ": holon.yaml must be a YAML mapping");
  return id;
}

inline std::filesystem::path discover_resolve_root(const std::filesystem::path &root) {
  std::error_code ec;
  auto absolute = std::filesystem::absolute(root, ec);
  if (ec) {
    absolute = root;
    ec.clear();
  }
  auto canonical = std::filesystem::weakly_canonical(absolute, ec);
  return ec ? absolute : canonical;
}

inline bool should_skip_discovery_dir(const std::string &name) {
  return name == ".git" || name == ".op" || name == "node_modules" ||
         name == "vendor" || name == "build" ||
         (!name.empty() && name.front() == '.');
}

inline size_t discovery_depth(const std::filesystem::path &path) {
  if (path.empty() || path == ".") {
    return 0;
  }
  return static_cast<size_t>(std::distance(path.begin(), path.end()));
}

inline void append_or_replace_entry(
    std::vector<HolonEntry> &entries,
    std::unordered_map<std::string, size_t> &index_by_key,
    const HolonEntry &candidate) {
  auto key = candidate.uuid.empty() ? candidate.dir.generic_string() : candidate.uuid;
  auto existing = index_by_key.find(key);
  if (existing != index_by_key.end()) {
    auto &current = entries[existing->second];
    if (discovery_depth(candidate.relative_path) <
        discovery_depth(current.relative_path)) {
      current = candidate;
    }
    return;
  }

  index_by_key.emplace(key, entries.size());
  entries.push_back(candidate);
}

inline HolonEntry parse_holon_entry(const std::filesystem::path &manifest_path,
                                    const std::filesystem::path &root,
                                    const std::string &origin) {
  HolonEntry entry;
  entry.identity = parse_holon(manifest_path.string());
  entry.slug = slug_from_identity(entry.identity);
  entry.uuid = entry.identity.uuid;
  entry.dir = discover_resolve_root(manifest_path.parent_path());
  entry.relative_path = entry.dir.lexically_relative(root);
  if (entry.relative_path.empty()) {
    entry.relative_path = ".";
  }
  entry.origin = origin;
  entry.manifest = parse_manifest(manifest_path.string());
  return entry;
}

inline std::vector<HolonEntry> discover_with_origin(
    const std::filesystem::path &root, const std::string &origin) {
  std::error_code ec;
  auto resolved_root = discover_resolve_root(root);
  if (!std::filesystem::exists(resolved_root, ec) ||
      !std::filesystem::is_directory(resolved_root, ec)) {
    return {};
  }

  std::vector<HolonEntry> entries;
  std::unordered_map<std::string, size_t> index_by_key;
  std::filesystem::recursive_directory_iterator it(
      resolved_root, std::filesystem::directory_options::skip_permission_denied, ec);
  std::filesystem::recursive_directory_iterator end;

  for (; it != end; it.increment(ec)) {
    if (ec) {
      ec.clear();
      continue;
    }

    const auto &path = it->path();
    if (it->is_directory(ec)) {
      if (ec) {
        ec.clear();
        continue;
      }
      if (should_skip_discovery_dir(path.filename().string())) {
        it.disable_recursion_pending();
      }
      continue;
    }

    if (ec || !it->is_regular_file(ec) || path.filename() != "holon.yaml") {
      ec.clear();
      continue;
    }

    try {
      append_or_replace_entry(entries, index_by_key,
                              parse_holon_entry(path, resolved_root, origin));
    } catch (const std::exception &) {
      continue;
    }
  }

  std::sort(entries.begin(), entries.end(),
            [](const HolonEntry &left, const HolonEntry &right) {
              auto left_rel = left.relative_path.generic_string();
              auto right_rel = right.relative_path.generic_string();
              if (left_rel != right_rel) {
                return left_rel < right_rel;
              }
              return left.uuid < right.uuid;
            });
  return entries;
}

inline std::filesystem::path oppath() {
  if (const char *configured = std::getenv("OPPATH");
      configured != nullptr && *configured != '\0') {
    return std::filesystem::path(configured);
  }
  if (const char *home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    return std::filesystem::path(home) / ".op";
  }
  return ".op";
}

inline std::filesystem::path opbin() {
  if (const char *configured = std::getenv("OPBIN");
      configured != nullptr && *configured != '\0') {
    return std::filesystem::path(configured);
  }
  return oppath() / "bin";
}

inline std::filesystem::path cache_dir() { return oppath() / "cache"; }

inline std::vector<HolonEntry> discover(const std::filesystem::path &root) {
  return discover_with_origin(root, "local");
}

inline std::vector<HolonEntry> discover_local() {
  return discover(std::filesystem::current_path());
}

inline std::vector<HolonEntry> discover_all() {
  std::vector<HolonEntry> merged;
  std::unordered_map<std::string, size_t> index_by_key;

  for (const auto &[root, origin] :
       std::vector<std::pair<std::filesystem::path, std::string>>{
           {std::filesystem::current_path(), "local"},
           {opbin(), "$OPBIN"},
           {cache_dir(), "cache"},
       }) {
    for (const auto &entry : discover_with_origin(root, origin)) {
      append_or_replace_entry(merged, index_by_key, entry);
    }
  }

  std::sort(merged.begin(), merged.end(),
            [](const HolonEntry &left, const HolonEntry &right) {
              auto left_rel = left.relative_path.generic_string();
              auto right_rel = right.relative_path.generic_string();
              if (left_rel != right_rel) {
                return left_rel < right_rel;
              }
              return left.uuid < right.uuid;
            });
  return merged;
}

inline std::optional<HolonEntry> find_by_slug(const std::string &slug) {
  for (const auto &entry : discover_all()) {
    if (entry.slug == slug) {
      return entry;
    }
  }
  return std::nullopt;
}

inline std::optional<HolonEntry> find_by_uuid(const std::string &prefix) {
  for (const auto &entry : discover_all()) {
    if (entry.uuid.rfind(prefix, 0) == 0) {
      return entry;
    }
  }
  return std::nullopt;
}

} // namespace holons
