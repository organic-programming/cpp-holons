#include "../include/holons/holons.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using json = nlohmann::json;

int connect_tcp(const std::string &host, int port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }

  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }

  return fd;
}

std::string make_temp_markdown_path() {
  char tmpl[] = "/tmp/holons_cpp_test_XXXXXX";
  int fd = ::mkstemp(tmpl);
  assert(fd >= 0);
  ::close(fd);
  std::string path = std::string(tmpl) + ".md";
  std::remove(tmpl);
  return path;
}

std::string resolve_go_binary() {
  std::string preferred = "/Users/bpds/go/go1.25.1/bin/go";
  if (::access(preferred.c_str(), X_OK) == 0) {
    return preferred;
  }
  return "go";
}

std::string find_sdk_dir() {
  char cwd[4096] = {0};
  if (::getcwd(cwd, sizeof(cwd)) == nullptr) {
    throw std::runtime_error("getcwd failed");
  }

  std::string dir(cwd);
  for (int i = 0; i < 12; ++i) {
    std::string candidate = dir + "/go-holons";
    if (::access(candidate.c_str(), F_OK) == 0) {
      return dir;
    }
    auto slash = dir.find_last_of('/');
    if (slash == std::string::npos || slash == 0) {
      break;
    }
    dir = dir.substr(0, slash);
  }

  throw std::runtime_error("unable to locate sdk directory containing go-holons");
}

bool read_line_with_timeout(int fd, std::string &out, int timeout_ms) {
  out.clear();
  int elapsed = 0;

  while (elapsed < timeout_ms) {
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int rc = ::poll(&pfd, 1, 100);
    if (rc < 0) {
      return false;
    }
    if (rc == 0) {
      elapsed += 100;
      continue;
    }
    if ((pfd.revents & POLLIN) == 0) {
      continue;
    }

    char ch = '\0';
    ssize_t n = ::read(fd, &ch, 1);
    if (n <= 0) {
      return false;
    }
    if (ch == '\n') {
      return true;
    }
    out.push_back(ch);
  }

  return false;
}

std::string read_available(int fd) {
  std::string out;
  char buf[1024];

  for (int i = 0; i < 20; ++i) {
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int rc = ::poll(&pfd, 1, 50);
    if (rc <= 0 || (pfd.revents & POLLIN) == 0) {
      if (!out.empty()) {
        break;
      }
      continue;
    }

    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    out.append(buf, static_cast<size_t>(n));
  }

  return out;
}

bool is_bind_restricted_errno(int err) {
  return err == EPERM || err == EACCES;
}

bool loopback_bind_restricted(std::string &reason) {
  reason.clear();

  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    reason = "socket() failed: " + std::string(std::strerror(errno));
    return false;
  }

  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(0);
  if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
    ::close(fd);
    reason = "inet_pton(127.0.0.1) failed";
    return false;
  }

  if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
    int err = errno;
    reason = std::strerror(err);
    ::close(fd);
    return is_bind_restricted_errno(err);
  }

  if (::listen(fd, 1) != 0) {
    int err = errno;
    reason = std::strerror(err);
    ::close(fd);
    return is_bind_restricted_errno(err);
  }

  ::close(fd);
  return false;
}

std::string read_file_text(const std::string &path) {
  std::ifstream file(path);
  if (!file.is_open()) {
    return "";
  }
  return std::string((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
}

int command_exit_code(const std::string &cmd) {
  int status = ::system(cmd.c_str());
  if (status == -1 || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

int run_bash_script(const std::string &script_body) {
  char path[] = "/tmp/holons_cpp_script_XXXXXX";
  int fd = ::mkstemp(path);
  if (fd < 0) {
    return -1;
  }

  FILE *script = ::fdopen(fd, "w");
  if (script == nullptr) {
    ::close(fd);
    ::unlink(path);
    return -1;
  }

  std::fputs("#!/usr/bin/env bash\n", script);
  std::fputs("set -euo pipefail\n", script);
  std::fputs(script_body.c_str(), script);
  if (std::ferror(script)) {
    std::fclose(script);
    ::unlink(path);
    return -1;
  }
  std::fclose(script);

  if (::chmod(path, 0700) != 0) {
    ::unlink(path);
    return -1;
  }

  int rc = command_exit_code(path);
  ::unlink(path);
  return rc;
}

const char *kGoHolonRPCServerSource = R"GO(
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"nhooyr.io/websocket"
)

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func main() {
	mode := "echo"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	var heartbeatCount int64
	var dropped int32

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:       []string{"holon-rpc"},
			InsecureSkipVerify: true,
		})
		if err != nil {
			http.Error(w, "upgrade failed", http.StatusBadRequest)
			return
		}
		defer c.CloseNow()

		ctx := r.Context()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}

			var msg rpcMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				_ = writeError(ctx, c, nil, -32700, "parse error")
				continue
			}
			if msg.JSONRPC != "2.0" {
				_ = writeError(ctx, c, msg.ID, -32600, "invalid request")
				continue
			}
			if msg.Method == "" {
				continue
			}

			switch msg.Method {
			case "rpc.heartbeat":
				atomic.AddInt64(&heartbeatCount, 1)
				_ = writeResult(ctx, c, msg.ID, map[string]interface{}{})
			case "echo.v1.Echo/Ping":
				var params map[string]interface{}
				_ = json.Unmarshal(msg.Params, &params)
				if params == nil {
					params = map[string]interface{}{}
				}
				_ = writeResult(ctx, c, msg.ID, params)
				if mode == "drop-once" && atomic.CompareAndSwapInt32(&dropped, 0, 1) {
					time.Sleep(100 * time.Millisecond)
					_ = c.Close(websocket.StatusNormalClosure, "drop once")
					return
				}
			case "echo.v1.Echo/HeartbeatCount":
				_ = writeResult(ctx, c, msg.ID, map[string]interface{}{"count": atomic.LoadInt64(&heartbeatCount)})
			case "echo.v1.Echo/CallClient":
				callID := "s1"
				if err := writeRequest(ctx, c, callID, "client.v1.Client/Hello", map[string]interface{}{"name": "go"}); err != nil {
					_ = writeError(ctx, c, msg.ID, 13, err.Error())
					continue
				}

				innerResult, callErr := waitForResponse(ctx, c, callID)
				if callErr != nil {
					_ = writeError(ctx, c, msg.ID, 13, callErr.Error())
					continue
				}
				_ = writeResult(ctx, c, msg.ID, innerResult)
			default:
				_ = writeError(ctx, c, msg.ID, -32601, fmt.Sprintf("method %q not found", msg.Method))
			}
		}
	})

	srv := &http.Server{Handler: h}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	fmt.Printf("ws://%s/rpc\n", ln.Addr().String())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func writeRequest(ctx context.Context, c *websocket.Conn, id interface{}, method string, params map[string]interface{}) error {
	payload, err := json.Marshal(rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  mustRaw(params),
	})
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, payload)
}

func writeResult(ctx context.Context, c *websocket.Conn, id interface{}, result interface{}) error {
	payload, err := json.Marshal(rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  mustRaw(result),
	})
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, payload)
}

func writeError(ctx context.Context, c *websocket.Conn, id interface{}, code int, message string) error {
	payload, err := json.Marshal(rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
		},
	})
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, payload)
}

func waitForResponse(ctx context.Context, c *websocket.Conn, expectedID string) (map[string]interface{}, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for {
		_, data, err := c.Read(deadlineCtx)
		if err != nil {
			return nil, err
		}

		var msg rpcMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		id, _ := msg.ID.(string)
		if id != expectedID {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("client error: %d %s", msg.Error.Code, msg.Error.Message)
		}
		var out map[string]interface{}
		if err := json.Unmarshal(msg.Result, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func mustRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return json.RawMessage(b)
}
)GO";

struct go_helper_server {
  pid_t pid = -1;
  int stdout_fd = -1;
  int stderr_fd = -1;
  std::string helper_path;

  ~go_helper_server() {
    if (pid > 0) {
      ::kill(pid, SIGTERM);
      int status = 0;
      for (int i = 0; i < 50; ++i) {
        pid_t rc = ::waitpid(pid, &status, WNOHANG);
        if (rc == pid) {
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      if (::waitpid(pid, &status, WNOHANG) == 0) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
      }
    }

    if (stdout_fd >= 0) {
      ::close(stdout_fd);
    }
    if (stderr_fd >= 0) {
      ::close(stderr_fd);
    }
    if (!helper_path.empty()) {
      std::remove(helper_path.c_str());
    }
  }
};

go_helper_server start_go_helper(const std::string &mode) {
  auto sdk_dir = find_sdk_dir();
  auto go_dir = sdk_dir + "/go-holons";

  auto stamp = std::to_string(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  std::string helper_path = go_dir + "/tmp-holonrpc-" + stamp + ".go";
  {
    std::ofstream out(helper_path);
    out << kGoHolonRPCServerSource;
  }

  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
    throw std::runtime_error("pipe() failed");
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    throw std::runtime_error("fork() failed");
  }

  if (pid == 0) {
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    ::close(err_pipe[0]);
    ::close(err_pipe[1]);
    ::chdir(go_dir.c_str());

    auto go = resolve_go_binary();
    std::vector<char *> argv;
    argv.push_back(const_cast<char *>(go.c_str()));
    argv.push_back(const_cast<char *>("run"));
    argv.push_back(const_cast<char *>(helper_path.c_str()));
    argv.push_back(const_cast<char *>(mode.c_str()));
    argv.push_back(nullptr);
    ::execvp(go.c_str(), argv.data());
    std::perror("execvp");
    ::_exit(127);
  }

  ::close(out_pipe[1]);
  ::close(err_pipe[1]);

  go_helper_server server;
  server.pid = pid;
  server.stdout_fd = out_pipe[0];
  server.stderr_fd = err_pipe[0];
  server.helper_path = helper_path;
  return server;
}

template <typename Func> void with_go_helper(const std::string &mode, Func f) {
  auto server = start_go_helper(mode);
  std::string url;
  if (!read_line_with_timeout(server.stdout_fd, url, 20000)) {
    auto stderr_text = read_available(server.stderr_fd);
    throw std::runtime_error("Go holon-rpc helper did not output URL: " +
                             stderr_text);
  }
  f(url);
}

go_helper_server start_cpp_holonrpc_server(const std::string &bind_url,
                                           bool once) {
  auto sdk_dir = find_sdk_dir();
  auto cpp_dir = sdk_dir + "/cpp-holons";

  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
    throw std::runtime_error("pipe() failed");
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    throw std::runtime_error("fork() failed");
  }

  if (pid == 0) {
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    ::close(out_pipe[0]);
    ::close(out_pipe[1]);
    ::close(err_pipe[0]);
    ::close(err_pipe[1]);
    ::chdir(cpp_dir.c_str());

    std::vector<std::string> args;
    args.emplace_back("./bin/holon-rpc-server");
    if (once) {
      args.emplace_back("--once");
    }
    args.emplace_back(bind_url);

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (auto &arg : args) {
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    ::execv(args[0].c_str(), argv.data());
    std::perror("execv");
    ::_exit(127);
  }

  ::close(out_pipe[1]);
  ::close(err_pipe[1]);

  go_helper_server server;
  server.pid = pid;
  server.stdout_fd = out_pipe[0];
  server.stderr_fd = err_pipe[0];
  return server;
}

template <typename Func> void with_cpp_holonrpc_server(Func f) {
  auto server = start_cpp_holonrpc_server("ws://127.0.0.1:0/rpc", true);
  std::string url;
  if (!read_line_with_timeout(server.stdout_fd, url, 20000)) {
    auto stderr_text = read_available(server.stderr_fd);
    throw std::runtime_error(
        "cpp holon-rpc server did not output URL: " + stderr_text);
  }

  f(url);

  int status = 0;
  if (::waitpid(server.pid, &status, 0) != server.pid) {
    throw std::runtime_error("waitpid() failed for cpp holon-rpc server");
  }
  server.pid = -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    throw std::runtime_error("cpp holon-rpc server exited with error");
  }
}

json invoke_eventually(holons::holon_rpc_client &client,
                       const std::string &method, const json &params) {
  std::exception_ptr last_error;
  for (int i = 0; i < 40; ++i) {
    try {
      return client.invoke(method, params);
    } catch (...) {
      last_error = std::current_exception();
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
  }
  if (last_error) {
    std::rethrow_exception(last_error);
  }
  throw std::runtime_error("invoke eventually failed");
}

} // namespace

int main() {
  int passed = 0;
  std::string bind_reason;
  bool bind_restricted = loopback_bind_restricted(bind_reason);

  // --- certification declarations ---
  {
    auto raw = read_file_text("cert.json");
    assert(!raw.empty());
    ++passed;
    assert(raw.find("\"echo_server\": \"./bin/echo-server\"") !=
           std::string::npos);
    ++passed;
    assert(raw.find("\"echo_client\": \"./bin/echo-client\"") !=
           std::string::npos);
    ++passed;
    assert(raw.find("\"holon_rpc_server\": \"./bin/holon-rpc-server\"") !=
           std::string::npos);
    ++passed;
    assert(raw.find("\"grpc_dial_tcp\": true") != std::string::npos);
    ++passed;
    assert(raw.find("\"grpc_dial_stdio\": true") != std::string::npos);
    ++passed;
    assert(raw.find("\"grpc_dial_ws\": true") != std::string::npos);
    ++passed;
    assert(raw.find("\"grpc_reject_oversize\": true") != std::string::npos);
    ++passed;
    assert(raw.find("\"holon_rpc_server\": true") != std::string::npos);
    ++passed;
  }

  // --- echo wrapper scripts ---
  {
    assert(::access("./bin/echo-client", F_OK) == 0);
    ++passed;
    assert(::access("./bin/echo-server", F_OK) == 0);
    ++passed;
    assert(::access("./bin/holon-rpc-server", F_OK) == 0);
    ++passed;
    assert(::access("./bin/echo-client", X_OK) == 0);
    ++passed;
    assert(::access("./bin/echo-server", X_OK) == 0);
    ++passed;
    assert(::access("./bin/holon-rpc-server", X_OK) == 0);
    ++passed;

    char fake_go[] = "/tmp/holons_cpp_fake_go_XXXXXX";
    char fake_log[] = "/tmp/holons_cpp_fake_go_log_XXXXXX";

    int fake_fd = ::mkstemp(fake_go);
    assert(fake_fd >= 0);
    int log_fd = ::mkstemp(fake_log);
    assert(log_fd >= 0);

    FILE *script = ::fdopen(fake_fd, "w");
    assert(script != nullptr);
    std::fprintf(
        script,
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        ": \"${HOLONS_FAKE_GO_LOG:?missing HOLONS_FAKE_GO_LOG}\"\n"
        "{\n"
        "  printf 'PWD=%%s\\n' \"$PWD\"\n"
        "  i=0\n"
        "  for arg in \"$@\"; do\n"
        "    printf 'ARG%%d=%%s\\n' \"$i\" \"$arg\"\n"
        "    i=$((i+1))\n"
        "  done\n"
        "} >\"$HOLONS_FAKE_GO_LOG\"\n");
    std::fclose(script);
    ::close(log_fd);
    assert(::chmod(fake_go, 0700) == 0);
    ++passed;

    char *prev_go_bin = std::getenv("GO_BIN");
    char *prev_log = std::getenv("HOLONS_FAKE_GO_LOG");
    char *prev_gocache = std::getenv("GOCACHE");

    std::string prev_go_bin_value = prev_go_bin ? prev_go_bin : "";
    std::string prev_log_value = prev_log ? prev_log : "";
    std::string prev_gocache_value = prev_gocache ? prev_gocache : "";

    bool had_prev_go_bin = prev_go_bin != nullptr;
    bool had_prev_log = prev_log != nullptr;
    bool had_prev_gocache = prev_gocache != nullptr;

    ::setenv("GO_BIN", fake_go, 1);
    ::setenv("HOLONS_FAKE_GO_LOG", fake_log, 1);
    ::unsetenv("GOCACHE");

    int client_exit = command_exit_code(
        "./bin/echo-client stdio:// --message cert-stdio >/dev/null 2>&1");
    assert(client_exit == 0);
    ++passed;

    auto capture = read_file_text(fake_log);
    assert(!capture.empty());
    ++passed;
    assert(capture.find("PWD=") != std::string::npos &&
           capture.find("/sdk/go-holons") != std::string::npos);
    ++passed;
    assert(capture.find("ARG0=run") != std::string::npos);
    ++passed;
    assert(capture.find("echo-client-go/main.go") != std::string::npos);
    ++passed;
    assert(capture.find("--sdk") != std::string::npos &&
           capture.find("cpp-holons") != std::string::npos);
    ++passed;
    assert(capture.find("--server-sdk") != std::string::npos &&
           capture.find("go-holons") != std::string::npos);
    ++passed;
    assert(capture.find("stdio://") != std::string::npos);
    ++passed;
    assert(capture.find("--message") != std::string::npos &&
           capture.find("cert-stdio") != std::string::npos);
    ++passed;

    int server_exit =
        command_exit_code("./bin/echo-server --listen stdio:// >/dev/null 2>&1");
    assert(server_exit == 0);
    ++passed;

    capture = read_file_text(fake_log);
    assert(!capture.empty());
    ++passed;
    assert(capture.find("PWD=") != std::string::npos &&
           capture.find("/sdk/go-holons") != std::string::npos);
    ++passed;
    assert(capture.find("ARG0=run") != std::string::npos);
    ++passed;
    assert(capture.find("echo-server-go/main.go") != std::string::npos);
    ++passed;
    assert(capture.find("--sdk") != std::string::npos &&
           capture.find("cpp-holons") != std::string::npos);
    ++passed;
    assert(capture.find("--max-recv-bytes") != std::string::npos &&
           capture.find("1572864") != std::string::npos);
    ++passed;
    assert(capture.find("--max-send-bytes") != std::string::npos &&
           capture.find("1572864") != std::string::npos);
    ++passed;
    assert(capture.find("--listen") != std::string::npos &&
           capture.find("stdio://") != std::string::npos);
    ++passed;

    server_exit = command_exit_code(
        "./bin/echo-server serve --listen stdio:// >/dev/null 2>&1");
    assert(server_exit == 0);
    ++passed;

    capture = read_file_text(fake_log);
    assert(!capture.empty());
    ++passed;
    assert(capture.find("ARG0=run") != std::string::npos);
    ++passed;
    assert(capture.find("echo-server-go/main.go") != std::string::npos);
    ++passed;
    assert(capture.find("serve") != std::string::npos);
    ++passed;
    assert(capture.find("--sdk") != std::string::npos &&
           capture.find("cpp-holons") != std::string::npos);
    ++passed;
    assert(capture.find("--max-recv-bytes") != std::string::npos &&
           capture.find("1572864") != std::string::npos);
    ++passed;
    assert(capture.find("--max-send-bytes") != std::string::npos &&
           capture.find("1572864") != std::string::npos);
    ++passed;
    assert(capture.find("--listen") != std::string::npos &&
           capture.find("stdio://") != std::string::npos);
    ++passed;

    int holonrpc_exit = command_exit_code(
        "./bin/holon-rpc-server ws://127.0.0.1:8080/rpc >/dev/null 2>&1");
    assert(holonrpc_exit == 0);
    ++passed;

    capture = read_file_text(fake_log);
    assert(!capture.empty());
    ++passed;
    assert(capture.find("PWD=") != std::string::npos &&
           capture.find("/sdk/go-holons") != std::string::npos);
    ++passed;
    assert(capture.find("ARG0=run") != std::string::npos);
    ++passed;
    assert(capture.find("holon-rpc-server-go/main.go") != std::string::npos);
    ++passed;
    assert(capture.find("--sdk") != std::string::npos &&
           capture.find("cpp-holons") != std::string::npos);
    ++passed;
    assert(capture.find("ws://127.0.0.1:8080/rpc") != std::string::npos);
    ++passed;

    if (had_prev_go_bin) {
      ::setenv("GO_BIN", prev_go_bin_value.c_str(), 1);
    } else {
      ::unsetenv("GO_BIN");
    }
    if (had_prev_log) {
      ::setenv("HOLONS_FAKE_GO_LOG", prev_log_value.c_str(), 1);
    } else {
      ::unsetenv("HOLONS_FAKE_GO_LOG");
    }
    if (had_prev_gocache) {
      ::setenv("GOCACHE", prev_gocache_value.c_str(), 1);
    } else {
      ::unsetenv("GOCACHE");
    }

    ::unlink(fake_go);
    ::unlink(fake_log);
  }

  // --- certification runtime transports ---
  {
    int mem_exit = command_exit_code(
        "./bin/echo-client --message cert-mem mem:// >/dev/null 2>&1");
    assert(mem_exit == 0);
    ++passed;

    if (bind_restricted) {
      std::fprintf(stderr, "SKIP: echo-client ws:// (%s)\n",
                   bind_reason.c_str());
      ++passed;
    } else {
      int ws_exit = command_exit_code(
          "./bin/echo-client --server-sdk cpp-holons --message cert-ws "
          "ws://127.0.0.1:0/grpc >/dev/null 2>&1");
      assert(ws_exit == 0);
      ++passed;
    }
  }

  // --- resilience probes (L5) ---
  if (bind_restricted) {
    std::fprintf(stderr, "SKIP: graceful shutdown probe (%s)\n",
                 bind_reason.c_str());
    ++passed;
    std::fprintf(stderr, "SKIP: timeout propagation probe (%s)\n",
                 bind_reason.c_str());
    ++passed;
    std::fprintf(stderr, "SKIP: oversized message rejection probe (%s)\n",
                 bind_reason.c_str());
    ++passed;
  } else {
    auto go = resolve_go_binary();

    {
      char script[8192];
      std::snprintf(
          script, sizeof(script),
          "cleanup() {\n"
          "  if [ -n \"${S_PID:-}\" ] && kill -0 \"$S_PID\" >/dev/null 2>&1; then\n"
          "    kill -TERM \"$S_PID\" >/dev/null 2>&1 || true\n"
          "    wait \"$S_PID\" >/dev/null 2>&1 || true\n"
          "  fi\n"
          "}\n"
          "trap cleanup EXIT\n"
          "S_OUT=$(mktemp)\n"
          "S_ERR=$(mktemp)\n"
          "./bin/echo-server --sleep-ms 1200 --listen tcp://127.0.0.1:0 >\"$S_OUT\" 2>\"$S_ERR\" &\n"
          "S_PID=$!\n"
          "ADDR=\"\"\n"
          "for _ in $(seq 1 120); do\n"
          "  if [ -s \"$S_OUT\" ]; then\n"
          "    ADDR=$(head -n1 \"$S_OUT\" | tr -d '\\r\\n')\n"
          "    if [ -n \"$ADDR\" ]; then break; fi\n"
          "  fi\n"
          "  sleep 0.05\n"
          "done\n"
          "[ -n \"$ADDR\" ]\n"
          "(cd ../go-holons && '%s' run ./cmd/echo-client --server-sdk cpp-holons --timeout-ms 5000 --message cert-l5-graceful \"$ADDR\" >/dev/null 2>&1) &\n"
          "C_PID=$!\n"
          "sleep 0.2\n"
          "kill -TERM \"$S_PID\"\n"
          "wait \"$C_PID\"\n"
          "wait \"$S_PID\"\n"
          "trap - EXIT\n",
          go.c_str());
      assert(run_bash_script(script) == 0);
      ++passed;
    }

    {
      char script[12288];
      std::snprintf(
          script, sizeof(script),
          "cleanup() {\n"
          "  if [ -n \"${S_PID:-}\" ] && kill -0 \"$S_PID\" >/dev/null 2>&1; then\n"
          "    kill -TERM \"$S_PID\" >/dev/null 2>&1 || true\n"
          "    wait \"$S_PID\" >/dev/null 2>&1 || true\n"
          "  fi\n"
          "}\n"
          "trap cleanup EXIT\n"
          "S_OUT=$(mktemp)\n"
          "S_ERR=$(mktemp)\n"
          "./bin/echo-server --sleep-ms 5000 --listen tcp://127.0.0.1:0 >\"$S_OUT\" 2>\"$S_ERR\" &\n"
          "S_PID=$!\n"
          "ADDR=\"\"\n"
          "for _ in $(seq 1 120); do\n"
          "  if [ -s \"$S_OUT\" ]; then\n"
          "    ADDR=$(head -n1 \"$S_OUT\" | tr -d '\\r\\n')\n"
          "    if [ -n \"$ADDR\" ]; then break; fi\n"
          "  fi\n"
          "  sleep 0.05\n"
          "done\n"
          "[ -n \"$ADDR\" ]\n"
          "TIME_OUT=$(mktemp)\n"
          "TIME_ERR=$(mktemp)\n"
          "set +e\n"
          "(cd ../go-holons && '%s' run ./cmd/echo-client --server-sdk cpp-holons --timeout-ms 2000 --message cert-l5-timeout \"$ADDR\" >\"$TIME_OUT\" 2>\"$TIME_ERR\")\n"
          "TIME_RC=$?\n"
          "set -e\n"
          "[ \"$TIME_RC\" -ne 0 ]\n"
          "grep -Eiq 'DeadlineExceeded|deadline exceeded' \"$TIME_ERR\"\n"
          "(cd ../go-holons && '%s' run ./cmd/echo-client --server-sdk cpp-holons --timeout-ms 8000 --message cert-l5-timeout-followup \"$ADDR\" >/dev/null 2>&1)\n"
          "kill -TERM \"$S_PID\"\n"
          "wait \"$S_PID\"\n"
          "trap - EXIT\n",
          go.c_str(), go.c_str());
      assert(run_bash_script(script) == 0);
      ++passed;
    }

    {
      char script[8192];
      std::snprintf(
          script, sizeof(script),
          "cleanup() {\n"
          "  if [ -n \"${S_PID:-}\" ] && kill -0 \"$S_PID\" >/dev/null 2>&1; then\n"
          "    kill -TERM \"$S_PID\" >/dev/null 2>&1 || true\n"
          "    wait \"$S_PID\" >/dev/null 2>&1 || true\n"
          "  fi\n"
          "}\n"
          "trap cleanup EXIT\n"
          "S_OUT=$(mktemp)\n"
          "S_ERR=$(mktemp)\n"
          "./bin/echo-server --listen tcp://127.0.0.1:0 >\"$S_OUT\" 2>\"$S_ERR\" &\n"
          "S_PID=$!\n"
          "ADDR=\"\"\n"
          "for _ in $(seq 1 120); do\n"
          "  if [ -s \"$S_OUT\" ]; then\n"
          "    ADDR=$(head -n1 \"$S_OUT\" | tr -d '\\r\\n')\n"
          "    if [ -n \"$ADDR\" ]; then break; fi\n"
          "  fi\n"
          "  sleep 0.05\n"
          "done\n"
          "[ -n \"$ADDR\" ]\n"
          "(cd ../go-holons && '%s' run ../cpp-holons/test/go_large_ping.go \"$ADDR\" >/dev/null 2>&1)\n"
          "kill -TERM \"$S_PID\"\n"
          "wait \"$S_PID\"\n"
          "trap - EXIT\n",
          go.c_str());
      assert(run_bash_script(script) == 0);
      ++passed;
    }
  }

  // --- scheme ---
  assert(holons::scheme("tcp://:9090") == "tcp");
  ++passed;
  assert(holons::scheme("unix:///tmp/x.sock") == "unix");
  ++passed;
  assert(holons::scheme("stdio://") == "stdio");
  ++passed;
  assert(holons::scheme("mem://") == "mem");
  ++passed;
  assert(holons::scheme("ws://host:8080") == "ws");
  ++passed;
  assert(holons::scheme("wss://host:443") == "wss");
  ++passed;

  // --- default URI ---
  assert(holons::kDefaultURI == "tcp://:9090");
  ++passed;

  // --- parse_uri ---
  {
    auto parsed = holons::parse_uri("wss://example.com:8443");
    assert(parsed.scheme == "wss");
    ++passed;
    assert(parsed.host == "example.com");
    ++passed;
    assert(parsed.port == 8443);
    ++passed;
    assert(parsed.path == "/grpc");
    ++passed;
    assert(parsed.secure);
    ++passed;
  }

  // --- listen tcp + runtime accept/read ---
  if (bind_restricted) {
    std::fprintf(stderr, "SKIP: listen tcp (%s)\n", bind_reason.c_str());
    ++passed;
  } else {
    auto lis = holons::listen("tcp://127.0.0.1:0");
    auto *tcp = std::get_if<holons::tcp_listener>(&lis);
    assert(tcp != nullptr);
    ++passed;

    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int rc = ::getsockname(tcp->fd, reinterpret_cast<sockaddr *>(&addr), &len);
    assert(rc == 0);
    ++passed;

    int port = ntohs(addr.sin_port);
    assert(port > 0);
    ++passed;

    int cfd = connect_tcp("127.0.0.1", port);
    assert(cfd >= 0);
    ++passed;

    auto server_conn = holons::accept(lis);
    assert(server_conn.scheme == "tcp");
    ++passed;

    const char *msg = "ping";
    auto wrote = ::write(cfd, msg, 4);
    assert(wrote == 4);
    ++passed;

    char buf[8] = {0};
    auto read_n = holons::conn_read(server_conn, buf, sizeof(buf));
    assert(read_n == 4);
    ++passed;
    assert(std::string(buf, 4) == "ping");
    ++passed;

    holons::close_connection(server_conn);
    ::close(cfd);
    holons::close_listener(lis);
  }

  // --- listen stdio/mem/ws ---
  {
    auto stdio_lis = holons::listen("stdio://");
    assert(std::holds_alternative<holons::stdio_listener>(stdio_lis));
    ++passed;

    auto stdio_conn = holons::accept(stdio_lis);
    assert(stdio_conn.scheme == "stdio");
    ++passed;
    holons::close_connection(stdio_conn);

    try {
      (void)holons::accept(stdio_lis);
      assert(false && "stdio second accept should throw");
    } catch (const std::runtime_error &) {
      ++passed;
    }

    auto mem_lis = holons::listen("mem://unit");
    assert(std::holds_alternative<holons::mem_listener>(mem_lis));
    ++passed;

    auto mem_client = holons::mem_dial(mem_lis);
    auto mem_server = holons::accept(mem_lis);
    assert(mem_client.scheme == "mem");
    ++passed;
    assert(mem_server.scheme == "mem");
    ++passed;

    const char *msg = "mem";
    auto mem_wrote = holons::conn_write(mem_client, msg, 3);
    assert(mem_wrote == 3);
    ++passed;

    char mem_buf[8] = {0};
    auto mem_read = holons::conn_read(mem_server, mem_buf, sizeof(mem_buf));
    assert(mem_read == 3);
    ++passed;
    assert(std::string(mem_buf, 3) == "mem");
    ++passed;

    holons::close_connection(mem_server);
    holons::close_connection(mem_client);
    holons::close_listener(mem_lis);

    auto ws_lis = holons::listen("ws://127.0.0.1:8080/holon");
    auto *ws = std::get_if<holons::ws_listener>(&ws_lis);
    assert(ws != nullptr);
    ++passed;
    assert(ws->host == "127.0.0.1");
    ++passed;
    assert(ws->port == 8080);
    ++passed;
    assert(ws->path == "/holon");
    ++passed;
    assert(!ws->secure);
    ++passed;

    try {
      (void)holons::accept(ws_lis);
      assert(false && "ws accept should throw");
    } catch (const std::runtime_error &) {
      ++passed;
    }
  }

  // --- unsupported URI ---
  try {
    (void)holons::listen("ftp://host");
    assert(false && "should have thrown");
  } catch (const std::invalid_argument &) {
    ++passed;
  }

  // --- parse_flags ---
  assert(holons::parse_flags({"--listen", "tcp://:8080"}) == "tcp://:8080");
  ++passed;
  assert(holons::parse_flags({"--port", "3000"}) == "tcp://:3000");
  ++passed;
  assert(holons::parse_flags({}) == "tcp://:9090");
  ++passed;

  // --- yaml_value ---
  assert(holons::yaml_value("uuid: \"abc-123\"") == "abc-123");
  ++passed;
  assert(holons::yaml_value("lang: rust") == "rust");
  ++passed;

  // --- parse_holon ---
  {
    std::string path = make_temp_markdown_path();
    {
      std::ofstream f(path);
      f << "---\nuuid: \"abc-123\"\ngiven_name: \"test\"\n"
        << "family_name: \"Test\"\nlang: \"cpp\"\n---\n# test\n";
    }
    auto id = holons::parse_holon(path);
    assert(id.uuid == "abc-123");
    ++passed;
    assert(id.given_name == "test");
    ++passed;
    assert(id.lang == "cpp");
    ++passed;
    std::remove(path.c_str());
  }

  // --- parse_holon missing frontmatter ---
  {
    std::string path = make_temp_markdown_path();
    {
      std::ofstream f(path);
      f << "# No frontmatter\n";
    }
    try {
      holons::parse_holon(path);
      assert(false && "should have thrown");
    } catch (const std::runtime_error &e) {
      assert(std::string(e.what()).find("frontmatter") != std::string::npos);
      ++passed;
    }
    std::remove(path.c_str());
  }

  // --- holon-rpc server interop (cpp wrapper) ---
  if (bind_restricted) {
    std::fprintf(stderr, "SKIP: holon-rpc server wrapper (%s)\n",
                 bind_reason.c_str());
    ++passed;
  } else {
    with_cpp_holonrpc_server([&](const std::string &url) {
      holons::holon_rpc_client client(250, 250, 100, 400);
      client.connect(url);
      auto out =
          client.invoke("echo.v1.Echo/Ping", json{{"message", "from-cpp"}});
      assert(out["message"].get<std::string>() == "from-cpp");
      ++passed;
      assert(out["sdk"].get<std::string>() == "cpp-holons");
      ++passed;
      client.close();
    });
    ++passed;
  }

  // --- holon-rpc client interop (Go helper) ---
  if (bind_restricted) {
    std::fprintf(stderr, "SKIP: holon-rpc Go helper (%s)\n",
                 bind_reason.c_str());
    ++passed;
  } else {
    {
      with_go_helper("echo", [&](const std::string &url) {
        holons::holon_rpc_client client(250, 250, 100, 400);
        client.connect(url);
        auto out =
            client.invoke("echo.v1.Echo/Ping", json{{"message", "hello"}});
        assert(out["message"].get<std::string>() == "hello");
        ++passed;
        client.close();
      });
    }

    {
      with_go_helper("echo", [&](const std::string &url) {
        holons::holon_rpc_client client(250, 250, 100, 400);
        client.register_handler("client.v1.Client/Hello",
                                [](const json &params) -> json {
                                  std::string name =
                                      params.value("name", std::string(""));
                                  return json{{"message", "hello " + name}};
                                });

        client.connect(url);
        auto out = client.invoke("echo.v1.Echo/CallClient", json::object());
        assert(out["message"].get<std::string>() == "hello go");
        ++passed;
        client.close();
      });
    }

    {
      with_go_helper("drop-once", [&](const std::string &url) {
        holons::holon_rpc_client client(200, 200, 100, 400);
        client.connect(url);

        auto first =
            client.invoke("echo.v1.Echo/Ping", json{{"message", "first"}});
        assert(first["message"].get<std::string>() == "first");
        ++passed;

        std::this_thread::sleep_for(std::chrono::milliseconds(700));

        auto second =
            invoke_eventually(client, "echo.v1.Echo/Ping",
                              json{{"message", "second"}});
        assert(second["message"].get<std::string>() == "second");
        ++passed;

        auto hb = invoke_eventually(client, "echo.v1.Echo/HeartbeatCount",
                                    json::object());
        assert(hb["count"].get<int>() >= 1);
        ++passed;

        client.close();
      });
    }
  }

  std::printf("%d passed, 0 failed\n", passed);
  return 0;
}
