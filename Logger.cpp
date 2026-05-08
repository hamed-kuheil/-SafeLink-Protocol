// =============================================================================
// SafeLink Protocol — src/Logger.cpp
// =============================================================================
//
// IMPLEMENTATION NOTES:
//
//   ASYNC QUEUE ARCHITECTURE:
//   ┌──────────────┐  log()   ┌──────────────┐  writer_thread  ┌──────────┐
//   │ Caller Thread│ ───────► │  log_queue_  │ ───────────────► │  File/  │
//   │ (any thread) │          │  (mutex-     │                  │  stderr │
//   └──────────────┘          │   guarded)   │                  └──────────┘
//                             └──────────────┘
//
//   The queue is bounded only by available memory. For a LAN tool this is
//   acceptable. A production hardened logger would add a max-queue-depth
//   and either drop or block on overflow.
//
//   TIMESTAMP PRECISION:
//   We use std::chrono::system_clock for wall-clock timestamps. On Linux this
//   is backed by clock_gettime(CLOCK_REALTIME) which has nanosecond resolution
//   (though the actual precision depends on the hardware timer).
//
// =============================================================================

#include "Logger.hpp"

#include <iomanip>    // std::put_time, std::setw, std::setfill
#include <iostream>   // std::cerr (only for mirroring to console — NOT for app logs)
#include <sstream>    // std::ostringstream

namespace SafeLink {

// =============================================================================
// Constructor / Destructor
// =============================================================================

Logger::Logger()
    : min_level_(LogLevel::INFO)
    , also_print_(true)
    , initialised_(false)
    , shutdown_requested_(false)
{
    // Constructor is intentionally minimal. The file handle and writer thread
    // are created in init() once the caller supplies the file path. This
    // prevents the race condition where the Meyers Singleton is constructed
    // before the application has determined where to write the log.
}

Logger::~Logger() {
    // If the application forgot to call shutdown(), we do it here as a safety
    // net. This may truncate in-flight entries if the destructor runs after
    // static object destruction (e.g., global std::ofstream), but it is better
    // than leaving the writer thread running with no owner.
    if (initialised_ && !shutdown_requested_.load()) {
        shutdown();
    }
}

// =============================================================================
// Singleton Access (Meyers Singleton)
// =============================================================================

Logger& Logger::instance() noexcept {
    // C++11 §6.7 guarantees this initialisation is thread-safe.
    // The 'static' keyword means the object is constructed exactly once,
    // the first time this function is called, and destroyed when the program
    // exits (in reverse construction order of all function-local statics).
    static Logger singleton;
    return singleton;
}

// =============================================================================
// Lifecycle: init()
// =============================================================================

void Logger::init(std::string_view log_file_path,
                  LogLevel         min_level,
                  bool             also_print)
{
    // Guard against double-initialisation (e.g., called from two threads
    // at startup, or called a second time after a soft restart).
    if (initialised_) {
        log(LogLevel::WARNING, "Logger", "init() called more than once — ignoring.",
            __FILE__, __LINE__);
        return;
    }

    min_level_.store(min_level);
    also_print_ = also_print;

    // Open the log file in append mode.
    // WHY append? If the application crashes and is restarted, appending to
    // the same file preserves the pre-crash log — invaluable for post-mortem
    // analysis. Overwriting would erase the evidence.
    if (!log_file_path.empty()) {
        file_stream_.open(std::string(log_file_path), std::ios::out | std::ios::app);
        if (!file_stream_.is_open()) {
            // Cannot use LOG_ERROR here (Logger not fully initialised yet).
            std::cerr << "[Logger] FATAL: Cannot open log file: "
                      << log_file_path << std::endl;
        }
    }

    initialised_ = true;

    // Start the asynchronous writer thread.
    // WHY std::thread and not std::jthread (C++20)?
    //   std::jthread would be cleaner (auto-join on destruction) but we target
    //   C++17 as the minimum. We manage joining manually in shutdown().
    writer_thread_ = std::thread(&Logger::writer_thread_func, this);

    // Log the first entry: a separator banner to make it easy to find where
    // a new run starts inside an appended log file.
    log(LogLevel::INFO, "Logger",
        "====== SafeLink Protocol Logger Initialised ======", __FILE__, __LINE__);

    log(LogLevel::INFO, "Logger",
        std::string("Minimum level : ") + log_level_to_string(min_level),
        __FILE__, __LINE__);

    if (file_stream_.is_open()) {
        log(LogLevel::INFO, "Logger",
            std::string("Log file      : ") + std::string(log_file_path),
            __FILE__, __LINE__);
    }
}

// =============================================================================
// Lifecycle: shutdown()
// =============================================================================

void Logger::shutdown() {
    if (!initialised_) return;

    log(LogLevel::INFO, "Logger",
        "====== SafeLink Protocol Logger Shutting Down ======", __FILE__, __LINE__);

    // Signal the writer thread that no more entries will be enqueued.
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        shutdown_requested_.store(true);
    }
    // Wake the writer thread so it can see the shutdown flag and exit its
    // blocking wait, even if the queue is currently empty.
    queue_cv_.notify_one();

    // Block until the writer thread drains the queue and exits.
    // WHY join (not detach)? A detached thread continues running after main()
    // returns, which is UB if it accesses objects that have been destroyed.
    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }

    // Flush and close the file.
    if (file_stream_.is_open()) {
        file_stream_.flush();
        file_stream_.close();
    }
}

// =============================================================================
// Core: log()
// =============================================================================

void Logger::log(LogLevel         level,
                 std::string_view component,
                 std::string      message,
                 std::string_view file,
                 int              line)
{
    // Fast-path filter: discard below-threshold messages without acquiring
    // the mutex. This is the most common case in a production system running
    // at INFO level with DEBUG calls scattered everywhere.
    if (static_cast<uint8_t>(level) < static_cast<uint8_t>(min_level_.load())) {
        return;
    }

    // Build the LogEntry on the stack.
    LogEntry entry;
    entry.level      = level;
    entry.component  = std::string(component);
    entry.message    = std::move(message);  // WHY move? avoids a heap copy
    entry.timestamp  = std::chrono::system_clock::now();
    entry.thread_id  = std::this_thread::get_id();

    // Strip the directory prefix from __FILE__ for brevity.
    // E.g., "/home/user/project/src/NetworkManager.cpp" → "NetworkManager.cpp"
    std::string_view file_sv(file);
    auto slash_pos = file_sv.rfind('/');
    if (slash_pos == std::string_view::npos) slash_pos = file_sv.rfind('\\');
    entry.file = (slash_pos != std::string_view::npos)
                    ? std::string(file_sv.substr(slash_pos + 1))
                    : std::string(file_sv);
    entry.line = line;

    // Enqueue the entry and notify the writer thread.
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        log_queue_.push(std::move(entry));
    }
    queue_cv_.notify_one();
}

// =============================================================================
// Private: writer_thread_func()
// =============================================================================

void Logger::writer_thread_func() {
    // This function runs on the dedicated writer thread for the lifetime of
    // the Logger (from init() to shutdown()).

    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex_);

        // Block until there is work to do OR shutdown is requested.
        // WHY a lambda predicate? std::condition_variable::wait() can wake
        // spuriously (the OS can unblock it without notify_one/all). The
        // predicate re-checks the condition and goes back to sleep if neither
        // queue entry nor shutdown flag is set.
        queue_cv_.wait(lock, [this] {
            return !log_queue_.empty() || shutdown_requested_.load();
        });

        // Drain the entire queue under the lock — we hold it already.
        // WHY drain all entries in one batch? Reduces the number of mutex
        // lock/unlock cycles compared to releasing and re-acquiring per entry.
        std::queue<LogEntry> local_batch;
        std::swap(local_batch, log_queue_);

        // Release the mutex BEFORE doing I/O.
        // WHY? I/O (especially file write) can take milliseconds. If we held
        // the mutex during I/O, every caller of log() would block for that
        // entire duration — defeating the purpose of async logging.
        lock.unlock();

        // Write each entry.
        while (!local_batch.empty()) {
            const LogEntry& entry = local_batch.front();
            std::string formatted = format_entry(entry);

            if (file_stream_.is_open()) {
                file_stream_ << formatted << '\n';
                // WHY not flush every entry? flush() forces an fwrite() +
                // fsync() which is very slow. We flush periodically or on
                // FATAL/ERROR. For a network security tool, losing the last
                // few log entries on a crash is acceptable; latency is not.
                if (entry.level >= LogLevel::ERROR) {
                    file_stream_.flush();
                }
            }

            if (also_print_) {
                std::cerr << formatted << '\n';
                if (entry.level >= LogLevel::ERROR) {
                    std::cerr.flush();
                }
            }

            local_batch.pop();
        }

        // Only exit the loop after we've drained any final entries that were
        // enqueued before shutdown_requested_ was set.
        if (shutdown_requested_.load()) {
            // One final flush to disk.
            if (file_stream_.is_open()) {
                file_stream_.flush();
            }
            break;
        }
    }
}

// =============================================================================
// Private: format_entry()
// =============================================================================

std::string Logger::format_entry(const LogEntry& entry) const {
    // Output format:
    //   [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] [Component         ] [T:XXXXXXXXXXXXXXXX] Message  (file.cpp:LINE)
    //
    // Example:
    //   [2025-06-10 14:32:01.547] [INFO ] [NetworkManager    ] [T:139812345] Listening on :54322  (NetworkManager.cpp:88)

    std::ostringstream oss;

    // --- Timestamp ---
    // Convert to time_t for strftime, then extract milliseconds separately.
    auto time_point = entry.timestamp;
    auto time_t_val = std::chrono::system_clock::to_time_t(time_point);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  time_point.time_since_epoch()) % 1000;

    // WHY gmtime? For a multi-node LAN tool it is important that all nodes
    // use the same timezone in their logs, otherwise correlating events across
    // nodes is confusing. UTC (gmtime) is the universal choice.
    // If local time is preferred, swap to localtime_r (POSIX) or localtime_s (MSVC).
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &time_t_val);
#else
    gmtime_r(&time_t_val, &tm_buf);
#endif

    oss << '[';
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setw(3) << std::setfill('0') << ms.count();
    oss << ']';

    // --- Log Level ---
    oss << " [" << log_level_to_string(entry.level) << ']';

    // --- Component (padded to 18 chars for alignment) ---
    oss << " [" << std::left << std::setw(18) << std::setfill(' ')
        << entry.component << ']';

    // --- Thread ID ---
    // WHY log the thread ID? When reading multi-threaded logs, thread IDs
    // help you group related lines (e.g., all activity for one connection).
    oss << " [T:" << entry.thread_id << ']';

    // --- Message ---
    oss << ' ' << entry.message;

    // --- Source Location (appended at end to not interrupt readability) ---
    oss << "  (" << entry.file << ':' << entry.line << ')';

    return oss.str();
}

} // namespace SafeLink
