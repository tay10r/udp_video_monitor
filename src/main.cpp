#include <uikit/main.hpp>

#include <imgui.h>
#include <implot.h>

#include <glad/glad.h>

#include <uv.h>

#include "stb_image.h"
#include "stb_image_write.h"

#include <chrono>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include <stdint.h>

#include <cassert>

#ifndef COMM_PORT
#define COMM_PORT 6255
#endif

namespace {

auto
to_handle(uv_udp_t* h) -> uv_handle_t*
{
  return reinterpret_cast<uv_handle_t*>(h);
}

using utc_clock = std::chrono::utc_clock;

using utc_time = std::chrono::utc_clock::time_point;

struct config final
{
  /**
   * @brief The address to broadcast the discovery request to.
   */
  std::string broadcast_ip{ "192.168.1.255" };
};

class jpeg_request;
class shutdown_request;

class interpreter
{
public:
  virtual void visit(const jpeg_request&) = 0;

  virtual void visit(const shutdown_request&) = 0;
};
/**
 * @brief A command issued from the UI to the worker thread.
 */
class command
{
public:
  virtual ~command() = default;

  virtual void accept(interpreter&) const = 0;
};

template<typename Derived>
class command_base : public command
{
public:
  ~command_base() override = default;

  void accept(interpreter& interp) const override { interp.visit(static_cast<const Derived&>(*this)); }
};

class jpeg_request final : public command_base<jpeg_request>
{
public:
  jpeg_request(std::string source_ip)
    : m_source_ip(std::move(source_ip))
  {
  }

  [[nodiscard]] auto source_ip() const -> const std::string& { return m_source_ip; }

private:
  std::string m_source_ip;
};

class shutdown_request final : public command_base<shutdown_request>
{
public:
};

class data_request final
{
public:
  enum class kind
  {
    discovery,
    camera
  };

  static void send(uv_udp_t* socket, const sockaddr* destination, const kind k)
  {
    std::unique_ptr<data_request> req(new data_request(k));

    if (!req->dispatch(socket, destination, /*broadcast=*/k == kind::discovery)) {
      return;
    }

    // deleted after send
    (void)req.release();
  }

protected:
  data_request(const kind k)
  {
    uv_handle_set_data(reinterpret_cast<uv_handle_t*>(&m_handle), this);

    static char discovery[] = "dsc?";
    static char camera[] = "jpg?";
    switch (k) {
      case kind::discovery:
        m_buffer.base = &discovery[0];
        m_buffer.len = 4;
        break;
      case kind::camera:
        m_buffer.base = &camera[0];
        m_buffer.len = 4;
        break;
    }
  }

  auto dispatch(uv_udp_t* socket, const sockaddr* destination, const bool broadcast) -> bool
  {
    uv_udp_set_broadcast(socket, broadcast ? 1 : 0);

    return uv_udp_send(&m_handle, socket, &m_buffer, 1, destination, on_send) == 0;
  }

  static void on_send(uv_udp_send_t* handle, const int status)
  {
    auto* self = static_cast<data_request*>(uv_handle_get_data(reinterpret_cast<uv_handle_t*>(handle)));

    delete self;
  }

private:
  uv_udp_send_t m_handle{};

  uv_buf_t m_buffer{};
};

class jpg_response;
class discovery_response;
class anomaly_response;

class response_visitor
{
public:
  virtual ~response_visitor() = default;

  virtual void visit(const jpg_response&) = 0;

  virtual void visit(const discovery_response&) = 0;

  virtual void visit(const anomaly_response&) = 0;
};

class response
{
public:
  virtual ~response() = default;

  virtual void accept(response_visitor& v) const = 0;
};

template<typename Derived>
class response_base : public response
{
public:
  void accept(response_visitor& v) const override { v.visit(static_cast<const Derived&>(*this)); }
};

class jpg_response final : public response_base<jpg_response>
{
public:
  jpg_response(unsigned char* data, int w, int h, std::string source_ip, utc_time timestamp)
    : m_data(data)
    , m_width(w)
    , m_height(h)
    , m_source_ip(std::move(source_ip))
    , m_timestamp(timestamp)
  {
  }

  ~jpg_response() { stbi_image_free(m_data); }

  [[nodiscard]] auto data() const -> const unsigned char* { return m_data; }

  [[nodiscard]] auto width() const -> int { return m_width; }

  [[nodiscard]] auto height() const -> int { return m_height; }

  [[nodiscard]] auto source_ip() const -> const std::string& { return m_source_ip; }

  [[nodiscard]] auto timestamp() const -> utc_time { return m_timestamp; }

private:
  unsigned char* m_data{ nullptr };

  int m_width{};

  int m_height{};

  std::string m_source_ip;

  utc_time m_timestamp;
};

class discovery_response final : public response_base<discovery_response>
{
public:
  explicit discovery_response(std::string ip_address)
    : m_ip_address(std::move(ip_address))
  {
  }

  [[nodiscard]] auto ip_address() const -> const std::string& { return m_ip_address; }

private:
  std::string m_ip_address;
};

class anomaly_response final : public response_base<anomaly_response>
{
public:
  anomaly_response(std::string source, const double timestamp, const double level)
    : source_(source)
    , timestamp_(timestamp)
    , level_(level)
  {
  }

  [[nodiscard]] auto get_source() const -> const std::string& { return source_; }

  [[nodiscard]] auto get_timestamp() const -> double { return timestamp_; }

  [[nodiscard]] auto get_level() const -> double { return level_; }

private:
  std::string source_;

  double timestamp_{};

  double level_{};
};

static uv_async_t
init_async(void* self)
{
  uv_async_t handle{};
  uv_handle_set_data(reinterpret_cast<uv_handle_t*>(&handle), self);
  return handle;
}

class timer final
{
public:
  using callback = void (*)(void*);

  timer(void* callback_data, callback cb)
    : m_data(callback_data)
    , m_callback(cb)
  {
    uv_handle_set_data(reinterpret_cast<uv_handle_t*>(&m_timer), this);
  }

  void init(uv_loop_t* loop, int interval)
  {
    uv_timer_init(loop, &m_timer);

    uv_timer_start(&m_timer, on_timeout, 0, interval);
  }

  void close() { uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr); }

protected:
  static void on_timeout(uv_timer_t* handle)
  {
    auto* self = static_cast<timer*>(uv_handle_get_data(reinterpret_cast<uv_handle_t*>(handle)));

    if (self->m_callback) {
      self->m_callback(self->m_data);
    }
  }

private:
  uv_timer_t m_timer{};

  void* m_data{};

  callback m_callback{};
};

using anomaly_cb = void (*)(void*, std::string source, double time, double level);

class anomaly_listener final
{
public:
  anomaly_listener(uv_loop_t* loop, void* cb_data, anomaly_cb cb)
    : cb_data_(cb_data)
    , cb_(cb)
  {
    uv_udp_init(loop, &socket_);

    uv_handle_set_data(to_handle(&socket_), this);
  }

  [[nodiscard]] auto setup(const char* ip, const int port) -> bool
  {
    sockaddr_in address{};

    if (uv_ip4_addr(ip, port, &address) != 0) {
      return false;
    }

    if (uv_udp_bind(&socket_, reinterpret_cast<const sockaddr*>(&address), UV_UDP_REUSEADDR) != 0) {
      return false;
    }

    return uv_udp_recv_start(&socket_, on_alloc, on_read) == 0;
  }

  void close() { uv_close(to_handle(&socket_), nullptr); }

protected:
  static auto get_self(uv_handle_t* handle) -> anomaly_listener*
  {
    return static_cast<anomaly_listener*>(uv_handle_get_data(handle));
  }

  static void on_alloc(uv_handle_t* handle, const size_t size, uv_buf_t* buf)
  {
    auto* self = get_self(handle);
    self->read_buffer_.resize(size);
    buf->base = reinterpret_cast<char*>(self->read_buffer_.data());
    buf->len = self->read_buffer_.size();
  }

  static void on_read(uv_udp_t* socket,
                      const ssize_t read_size,
                      const uv_buf_t* buf,
                      const sockaddr* sender,
                      unsigned int)
  {
    if (read_size < 0) {
      // error
      return;
    }

    if (read_size != 16) {
      // we should just have two 64-bit floats: the timestamp and anomaly level
      return;
    }

    if (!sender || (sender->sa_family != AF_INET)) {
      return;
    }

    std::string source;

    source.resize(256);

    const auto ret = uv_ip4_name(reinterpret_cast<const sockaddr_in*>(sender), source.data(), source.size());
    if (ret != 0) {
      return;
    }
    const auto null_terminator = source.find('\0');
    if (null_terminator != std::string::npos) {
      source.resize(null_terminator);
    }

    auto* self = get_self(to_handle(socket));
    auto* data = reinterpret_cast<const double*>(buf->base);
    const auto timestamp = data[0];
    const auto level = data[1];
    if (self->cb_) {
      self->cb_(self->cb_data_, std::move(source), timestamp, level);
    }
  }

private:
  uv_udp_t socket_{};

  std::vector<uint8_t> read_buffer_;

  void* cb_data_{};

  anomaly_cb cb_{};
};

class worker final : public interpreter
{
public:
  explicit worker(const config& cfg)
    : m_command_handle(init_async(this))
    , m_thread(&worker::run_thread, this)
  {
  }

  void issue_command(std::unique_ptr<command> cmd)
  {
    {
      std::lock_guard lock(m_command_lock);
      m_command_queue.emplace_back(std::move(cmd));
    }

    uv_async_send(&m_command_handle);
  }

  auto poll() -> std::vector<std::unique_ptr<response>>
  {
    std::lock_guard lock(m_lock);
    return std::move(m_responses);
  }

  void shutdown()
  {
    issue_command(std::make_unique<shutdown_request>());

    m_thread.join();
  }

protected:
  void add_response(std::unique_ptr<response> r)
  {
    std::lock_guard<std::mutex> lock(m_lock);
    m_responses.emplace_back(std::move(r));
  }

  static void on_command(uv_async_t* handle)
  {
    auto* self = static_cast<worker*>(uv_handle_get_data(reinterpret_cast<uv_handle_t*>(handle)));

    std::vector<std::unique_ptr<command>> cmds;
    {
      std::lock_guard lock(self->m_command_lock);
      cmds = std::move(self->m_command_queue);
    }
    for (auto& cmd : cmds) {
      cmd->accept(*self);
    }
  }

  static void on_anomaly(void* self_ptr, std::string source, double timestamp, double anomaly)
  {
    auto* self = static_cast<worker*>(self_ptr);
    auto r = std::make_unique<anomaly_response>(std::move(source), timestamp, anomaly);
    self->add_response(std::move(r));
  }

  void run_thread()
  {
    if (const auto err = uv_ip4_addr(m_config.broadcast_ip.c_str(), COMM_PORT, &m_broadcast_address); err) {
      // TODO : send error message to UI
      return;
    }

    uv_loop_init(&m_loop);

    uv_async_init(&m_loop, &m_command_handle, on_command);

    uv_handle_set_data(reinterpret_cast<uv_handle_t*>(&m_socket), this);

    anomaly_listener anomaly_listener_(&m_loop, this, on_anomaly);

    anomaly_listener_.setup("0.0.0.0", 5205);

    uv_udp_init(&m_loop, &m_socket);

    uv_udp_recv_start(&m_socket, on_alloc, on_read);

    m_broadcast_timer.init(&m_loop, 1000);

    uv_run(&m_loop, UV_RUN_DEFAULT);

    /* close */

    anomaly_listener_.close();

    m_broadcast_timer.close();

    uv_close(reinterpret_cast<uv_handle_t*>(&m_socket), nullptr);

    uv_close(reinterpret_cast<uv_handle_t*>(&m_command_handle), nullptr);

    uv_run(&m_loop, UV_RUN_DEFAULT);

    uv_loop_close(&m_loop);
  }

  static void on_alloc(uv_handle_t* handle, const size_t size, uv_buf_t* buf)
  {
    auto* self = static_cast<worker*>(uv_handle_get_data(handle));
    self->m_read_buffer.resize(size);
    buf->base = reinterpret_cast<char*>(&self->m_read_buffer[0]);
    buf->len = size;
  }

  static auto to_ip4(const sockaddr* addr) -> std::string
  {
    if (addr->sa_family != AF_INET) {
      return "";
    }

    std::string name;
    name.resize(UV_IF_NAMESIZE);
    const auto ret = uv_ip4_name(reinterpret_cast<const sockaddr_in*>(addr), &name[0], name.size());
    if (ret != 0) {
      return "";
    }

    // Ensure that there is a null terminator in the name.
    name.push_back(static_cast<char>(0));
    for (std::size_t i = 0; i < name.size(); i++) {
      if (name[i] == 0) {
        name.resize(i);
        break;
      }
    }

    return name;
  }

  auto handle_jpeg(const sockaddr* sender) -> bool
  {
    const auto timestamp = utc_clock::now();

    if (m_read_buffer.size() < 4) {
      return false;
    }

    auto ip = to_ip4(sender);
    if (ip.empty()) {
      // TODO : log error
      return false;
    }

    int w = 0;
    int h = 0;
    auto* data = stbi_load_from_memory(m_read_buffer.data() + 4, m_read_buffer.size() - 4, &w, &h, nullptr, 1);
    if (!data) {
      return false;
    }
    auto r = std::make_unique<jpg_response>(data, w, h, std::move(ip), timestamp);
    add_response(std::move(r));
    return true;
  }

  auto handle_discovery_reply(const sockaddr* sender) -> bool
  {
    auto name = to_ip4(sender);
    if (name.empty()) {
      // TODO : log error
      return false;
    }
    add_response(std::make_unique<discovery_response>(std::move(name)));
    return true;
  }

  static void on_read(uv_udp_t* socket,
                      const ssize_t read_size,
                      const uv_buf_t* buf,
                      const sockaddr* sender,
                      const unsigned int)
  {
    if (read_size < 4) {
      return;
    }

    auto* self = static_cast<worker*>(uv_handle_get_data(reinterpret_cast<uv_handle_t*>(socket)));

    const char* ptr = buf->base;

    const char type[5]{ ptr[0], ptr[1], ptr[2], ptr[3], 0 };

    if (std::strcmp(type, "jpg+") == 0) {
      self->handle_jpeg(sender);
    } else if (std::strcmp(type, "dsc+") == 0) {
      self->handle_discovery_reply(sender);
    }
  }

  void issue_video_request(const std::string& ip)
  {
    sockaddr_in address{};

    if (const auto err = uv_ip4_addr(ip.c_str(), COMM_PORT, &address); err) {
      // TODO : log error
      return;
    }

    data_request::send(&m_socket, reinterpret_cast<const sockaddr*>(&address), data_request::kind::camera);
  }

  static void on_broadcast_interval(void* self_ptr)
  {
    auto* self = static_cast<worker*>(self_ptr);

    data_request::send(
      &self->m_socket, reinterpret_cast<const sockaddr*>(&self->m_broadcast_address), data_request::kind::discovery);
  }

  void visit(const shutdown_request&) override { uv_stop(&m_loop); }

  void visit(const jpeg_request& req) override { issue_video_request(req.source_ip()); }

private:
  config m_config;

  uv_async_t m_command_handle{};

  std::thread m_thread;

  /**
   * @brief The loop that all the IO code is running with.
   */
  uv_loop_t m_loop{};

  /**
   * @brief The socket for receiving broadcast messages and issuing requests.
   */
  uv_udp_t m_socket{};

  /**
   * @brief The address to broadcast to when looking for devices.
   */
  sockaddr_in m_broadcast_address{};

  /**
   * @brief This timer invokes the discovery process.
   */
  uv_timer_t m_discovery_timer{};

  std::vector<std::uint8_t> m_read_buffer;

  std::mutex m_lock;

  std::vector<std::unique_ptr<response>> m_responses;

  std::mutex m_command_lock;

  std::vector<std::unique_ptr<command>> m_command_queue;

  timer m_broadcast_timer{ this, on_broadcast_interval };
};

struct stream_context final
{
  /**
   * @brief Whether or not this stream is enabled.
   */
  bool enabled{ true };

  /**
   * @brief Whether or not the stream was rendered in the last frame.
   */
  bool visible{ true };

  /**
   * @brief The number of seconds since the last image update.
   */
  float time_since_update{ std::numeric_limits<float>::infinity() };

  /**
   * @brief If it has been this many seconds since the last update, issue another render request.
   */
  float timeout{ 1.0f };

  /**
   * @brief Whether to record frames.
   */
  bool record{ false };

  /**
   * @brief The aspect ratio of the image.
   */
  float aspect{ 1.0F };

  /**
   * @brief The OpenGL texture containing the latest frame data.
   */
  GLuint texture{};

  ImPlotContext* context{};

  stream_context()
  {
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    context = ImPlot::CreateContext();
  }

  stream_context(const stream_context&) = delete;

  ~stream_context()
  {
    glDeleteTextures(1, &texture);

    ImPlot::DestroyContext(context);
  }
};

struct time_series final
{
  std::size_t max_size{ 4096 };

  std::vector<double> time_data;

  std::vector<double> y_data;

  void push_sample(double time, double y)
  {
    if (time_data.size() >= max_size) {
      time_data.erase(time_data.begin());
      y_data.erase(y_data.begin());
    }
    time_data.emplace_back(time);
    y_data.emplace_back(y);
  }
};

class app_impl final
  : public uikit::app
  , public response_visitor
{
public:
  void setup(uikit::platform& plt) override
  {
    plt.set_app_name("Monitor");

    m_worker = std::make_unique<worker>(m_config);
  }

  void teardown(uikit::platform& plt) override
  {
    m_worker->shutdown();

    m_stream_map.clear();
  }

  void loop(uikit::platform& plt) override
  {
    auto responses = m_worker->poll();
    for (const auto& r : responses) {
      r->accept(*this);
    }

    ImGui::DockSpaceOverViewport();

    auto& io = ImGui::GetIO();

    // update states
    for (auto& entry : m_stream_map) {
      entry.second->time_since_update += io.DeltaTime;
      entry.second->visible = false /* Note: it gets marked as visible if the code that renders it is reached. */;
    }

    render_streams();

    if (ImGui::Begin("Anomaly Chart")) {
      render_anomaly_chart();
    }
    ImGui::End();
  }

protected:
  void render_anomaly_chart()
  {
    if (ImGui::Button("Clear")) {
      m_anomaly_map.clear();
    }

    if (!ImPlot::BeginPlot("Anomaly Chart", ImVec2(-1, -1), ImPlotFlags_Crosshairs | ImPlotFlags_NoFrame)) {
      return;
    }

    ImPlot::SetupAxes("Time", "Anomaly Level", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);

    ImPlot::SetupAxisScale(ImAxis_X1, ImPlotScale_Time);

    for (const auto& entry : m_anomaly_map) {
      ImPlot::PlotLine(
        entry.first.c_str(), entry.second.time_data.data(), entry.second.y_data.data(), entry.second.time_data.size());
    }

    ImPlot::EndPlot();
  }

  void render_stream(const std::string& ip, stream_context& ctx)
  {
    ImPlot::SetCurrentContext(ctx.context);

    if (!ctx.enabled) {
      return;
    }

    ctx.visible = true;

    if (ctx.time_since_update > ctx.timeout) {
      request_new_frame(ip, ctx);
    }

    if (ImGui::Button(ctx.record ? "Stop Recording" : "Start Recording")) {
      ctx.record = !ctx.record;
    }

    ImGui::SameLine();

    ImGui::Text("Time since update: %.2f [sec]", ctx.time_since_update);

    ImGui::Separator();

    if (ImPlot::BeginPlot("##Plot", ImVec2(-1, -1), ImPlotFlags_NoFrame | ImPlotFlags_NoLegend | ImPlotFlags_Equal)) {

      ImPlot::SetupAxes("", "", ImPlotAxisFlags_NoDecorations, ImPlotAxisFlags_NoDecorations);

      ImPlot::PlotImage("##Image",
                        reinterpret_cast<ImTextureID>(ctx.texture),
                        ImPlotPoint(-ctx.aspect * 0.5F, 0),
                        ImPlotPoint(ctx.aspect * 0.5F, 1));

      ImPlot::EndPlot();
    }
  }

  void render_streams()
  {
    for (auto& entry : m_stream_map) {
      if (ImGui::Begin(entry.first.c_str())) {
        render_stream(entry.first, *entry.second);
      }
      ImGui::End();
    }
  }

  void visit(const discovery_response& r) override
  {
    const auto& remote_host = r.ip_address();

    assert(!remote_host.empty());

    if (const auto it = m_stream_map.find(remote_host); it != m_stream_map.end()) {
      // Already known
      return;
    }

    m_stream_map.emplace(remote_host, std::make_unique<stream_context>());
  }

  void visit(const jpg_response& r) override
  {
    auto it = m_stream_map.find(r.source_ip());
    if (it == m_stream_map.end()) {
      // TODO : log error
      return;
    }

    it->second->time_since_update = 0.0f;

    it->second->aspect = static_cast<float>(r.width()) / static_cast<float>(r.height());

    glBindTexture(GL_TEXTURE_2D, it->second->texture);

    const auto* bw_data = r.data();
    std::vector<std::uint8_t> rgb_data(r.width() * r.height() * 3);
    for (std::size_t i = 0; i < r.width() * r.height(); i++) {
      rgb_data[i * 3 + 0] = bw_data[i];
      rgb_data[i * 3 + 1] = bw_data[i];
      rgb_data[i * 3 + 2] = bw_data[i];
    }

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, r.width(), r.height(), 0, GL_RGB, GL_UNSIGNED_BYTE, rgb_data.data());

    if (it->second->record) {
      record_frame(r, it->first);
    }

    if (it->second->visible) {
      request_new_frame(it->first, *it->second);
    }
  }

  void visit(const anomaly_response& r) override
  {
    auto it = m_anomaly_map.find(r.get_source());
    if (it == m_anomaly_map.end()) {
      it = m_anomaly_map.emplace(r.get_source(), time_series{}).first;
    }
    it->second.push_sample(r.get_timestamp(), r.get_level());
  }

  void record_frame(const jpg_response& r, const std::string& ip)
  {
    const std::filesystem::path data_path{ "data" };

    std::filesystem::create_directory(data_path);

    const std::filesystem::path ip_path{ data_path / ip };

    std::filesystem::create_directory(ip_path);

    std::ostringstream name_stream;
    name_stream << r.timestamp().time_since_epoch().count();
    name_stream << ".png";

    const std::filesystem::path img_path{ ip_path / name_stream.str() };

    stbi_write_png(img_path.string().c_str(), r.width(), r.height(), 1, r.data(), r.width());
  }

  void request_new_frame(const std::string& ip, stream_context& ctx)
  {
    m_worker->issue_command(std::make_unique<jpeg_request>(ip));

    ctx.time_since_update = 0.0;
  }

private:
  config m_config;

  std::unique_ptr<worker> m_worker;

  std::map<std::string, std::unique_ptr<stream_context>> m_stream_map;

  std::map<std::string, time_series> m_anomaly_map;
};

} // namespace

namespace uikit {

auto
app::create() -> std::unique_ptr<app>
{
  return std::make_unique<app_impl>();
}

} // namespace uikit
