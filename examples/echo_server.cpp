#include "holons/serve.hpp"

#include "echo/v1/echo.grpc.pb.h"

class EchoServiceImpl final : public echo::v1::Echo::Service {
public:
  grpc::Status Ping(grpc::ServerContext *,
                    const echo::v1::PingRequest *request,
                    echo::v1::PingResponse *response) override {
    response->set_message(request->message());
    response->set_sdk(request->sdk().empty() ? "cpp-holons"
                                             : request->sdk());
    return grpc::Status();
  }
};

int main(int argc, char **argv) {
  std::vector<std::string> args;
  args.reserve(static_cast<size_t>(std::max(argc - 1, 0)));
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  if (!args.empty() && args.front() == "serve") {
    args.erase(args.begin());
  }

  auto listeners = holons::serve::parse_flags(args);
  EchoServiceImpl service;
  holons::serve::serve(listeners, [&service](grpc::ServerBuilder &builder) {
    builder.RegisterService(&service);
  });
  return 0;
}
