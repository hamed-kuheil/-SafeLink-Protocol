// =============================================================================
// SafeLink Protocol — include/Logger.hpp
// =============================================================================
//
// PURPOSE:
//   Provides a singleton, thread-safe, multi-level logging facility.
//   Every system event in SafeLink MUST be recorded through this interface.
//
// DESIGN RATIONALE — "Why a dedicated Logger and not std::cout?":
//   1. THREAD SAFETY: std::cout is not thread-safe. Concurrent writes from
//      the network thread, security thread, and UI thread will interleave
//      characters, producing unreadable output. This Logger serialises all
//      writes through a std::mutex.
//
//   2. LEVEL FILTERING: std::cout has no concept of severity. The Logger
//      lets you set a minimum level at startup (e.g., WARNING in production,
//      DEBUG in development) and silently drop everything below it.
//
//   3. PERSISTENT RECORD: std::cout disappears on terminal close. File
//      logging creates an audit trail — indispensable when debugging intermittent
//      network or cryptography failures that happen after you close your terminal.
//
//   4. STRUCTURED OUTPUT: Each log line includes a timestamp, level tag,
//      source location (file/line), and thread ID. Grepping for [ERROR] in a
//      10 000-line log is far more tractable than reading raw std::cout output.
//
//   5. SEPARATION OF CONCERNS: Library code (NetworkManager, SecurityManager)
//      should never write directly to I/O streams. The Logger is the single
//      I/O surface for all diagnostic output.
//
// SINGLETON PATTERN CHOICE:
//   We use a Meyers Singleton (function-local static). In C++11+ the standard
//   guarantees that the initialisation of a function-local static is thread-safe
//   (§6.7 [stmt.dcl]). This eliminates the double-checked locking pattern
//   and its associated pitfalls entirely.
//
// USAGE EXAMPLE:
//   Logger::instance().init("safelink.log", LogLevel::DEBUG);
//   LOG_INFO("NetworkManager", "Listening on port {}", 54322);
//   LOG_ERROR("SecurityManager", "GCM tag verification FAILED for seq={}", seq);
//
// =============================================================================

#pragma once

#include <atomic>       // std::atomic<bool> for flush-on-request flag
#include <chrono>       // std::chrono::system_clock for timestamps
#include <condition_variable> // std::condition_variable for async flush
#include <cstdint>      // uint32_t
#include <fstream>      // std::ofstream for file output
#include <memory>       // std::unique_ptr
#include <mutex>        // std::mutex, std::lock_guard
#include <queue>        // std::queue for async log buffer
#include <sstream>      // std::ostringstream for formatting
#include <string>       // std::string
#include <string_view>  // std::string_view — non-owning, zero-copy string arg
#include <thread>       // std::thread for async writer


namespace SafeLink {

// =============================================================================
// SECTION 1: Log Level Enum
// =============================================================================

/// Severity levels in ascending order of importance.
/// WHY enum class? See ProtocolHandler.hpp for the rationale — scoping and
/// strong typing prevent accidental comparison with unrelated integers.
enum class LogLevel : uint8_t {
    TRACE   = 0,  ///< Extremely verbose; byte-level dumps, function entry/exit.
    DEBUG   = 1,  ///< Developer diagnostics; state changes, branch decisions.
    INFO    = 2,  ///< Normal operational milestones; connection established, etc.
    WARNING = 3,  ///< Recoverable anomalies; retry attempts, deprecated usage.
    ERROR   = 4,  ///< Non-fatal errors; failed operations that were recovered.
    FATAL   = 5,  ///< Unrecoverable errors; the process will terminate shortly.
};

/// Convert a LogLevel to its short string tag (e.g., LogLevel::INFO → "INFO ").
/// WHY inline? This is called on every log entry. Declaring it inline here
/// avoids the overhead of a function call for a switch with 6 arms.
inline const char* log_level_to_string(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::TRACE:   return "TRACE";
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO ";
        case LogLevel::WARNING: return "WARN ";
        case LogLevel::ERROR:   return "ERROR";
        case LogLevel::FATAL:   return "FATAL";
        default:                return "?????";
    }
}


// =============================================================================
// SECTION 2: Logger Class
// =============================================================================

class Logger {
public:
    // -------------------------------------------------------------------------
    // Singleton Access
    // -------------------------------------------------------------------------

    /// Returns the single Logger instance (Meyers Singleton, thread-safe).
    ///
    /// WHY not a global variable?
    ///   Global variables suffer from the "static initialisation order fiasco" —
    ///   if another translation unit's global tries to log during its own
    ///   initialisation, the Logger global might not be constructed yet.
    ///   The Meyers Singleton is initialised on first use, so it is always
    ///   ready before the first call.
    static Logger& instance() noexcept;

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /// Initialise the logger: open the log file and start the async writer thread.
    ///
    /// @param  log_file_path  Filesystem path for the log file.
    ///                        Pass "" to disable file output (console only).
    /// @param  min_level      Minimum severity to record. Messages below this
    ///                        level are silently discarded.
    /// @param  also_print     If true, mirror every log line to stderr in
    ///                        addition to the file. Useful during development.
    ///
    /// WHY an explicit init() method rather than doing it in the constructor?
    ///   The singleton's constructor runs before main() for global-scope loggers.
    ///   We want the application (main.cpp) to control WHERE the log file goes
    ///   and WHAT level to use at runtime — information not available before main().
    void init(std::string_view log_file_path,
              LogLevel         min_level   = LogLevel::INFO,
              bool             also_print  = true);

    /// Flush all pending log entries and close the file cleanly.
    /// MUST be called before program exit to avoid losing buffered entries.
    void shutdown();

    // -------------------------------------------------------------------------
    // Core Log Method
    // -------------------------------------------------------------------------

    /// Write a single log entry.
    ///
    /// @param  level      Severity of this message.
    /// @param  component  Short identifier for the calling subsystem
    ///                    (e.g., "NetworkManager", "SecurityManager").
    ///                    Used for filtering and grep-ability.
    /// @param  message    The formatted log message string.
    /// @param  file       Source file name (__FILE__ from macro).
    /// @param  line       Source line number (__LINE__ from macro).
    ///
    /// Thread-safety guarantee: this method can be called concurrently from
    /// any number of threads. The entry is placed on a lock-protected queue
    /// and written by a single dedicated writer thread, which eliminates
    /// lock contention in the callers' hot paths.
    void log(LogLevel         level,
             std::string_view component,
             std::string      message,
             std::string_view file,
             int              line);

    // -------------------------------------------------------------------------
    // Runtime Configuration
    // -------------------------------------------------------------------------

    /// Change the minimum log level at runtime (e.g., to enable debug logging
    /// dynamically via a signal handler or CLI command).
    /// WHY std::atomic? level_ is read on every log() call from multiple
    /// threads. A std::atomic<LogLevel> allows lock-free reads.
    void set_level(LogLevel level) noexcept { min_level_.store(level); }

    /// Query the current minimum level.
    LogLevel get_level() const noexcept { return min_level_.load(); }

    // -------------------------------------------------------------------------
    // Deleted Copy/Move — Singletons must not be copied
    // -------------------------------------------------------------------------
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&)                 = delete;
    Logger& operator=(Logger&&)      = delete;

private:
    // -------------------------------------------------------------------------
    // Private Constructor / Destructor (Singleton enforcement)
    // -------------------------------------------------------------------------
    Logger();
    ~Logger();

    // -------------------------------------------------------------------------
    // Internal Log Entry Structure
    // -------------------------------------------------------------------------

    /// A single pending log entry sitting on the async queue.
    struct LogEntry {
        LogLevel    level;
        std::string component;
        std::string message;
        std::string file;
        int         line;
        /// Pre-captured timestamp avoids timestamp skew between when the
        /// entry was created and when the writer thread processes it.
        std::chrono::system_clock::time_point timestamp;
        std::thread::id thread_id;
    };

    // -------------------------------------------------------------------------
    // Async Writer Infrastructure
    // -------------------------------------------------------------------------

    /// Background thread that drains the log queue and writes to the file.
    /// WHY async? Because writing to a file involves a syscall (write()) which
    /// can block on a slow disk, NFS mount, or full buffer. If we wrote
    /// synchronously in the caller's thread, a disk stall could delay the
    /// network thread and cause connection timeouts.
    void writer_thread_func();

    /// Format a LogEntry into a single line string.
    /// Example output:
    ///   [2025-06-10 14:32:01.547] [INFO ] [NetworkManager] [T:140234] Listening on :54322  (main.cpp:88)
    std::string format_entry(const LogEntry& entry) const;

    // -------------------------------------------------------------------------
    // Member Variables
    // -------------------------------------------------------------------------

    std::ofstream                   file_stream_;    ///< Output file handle.
    std::atomic<LogLevel>           min_level_;      ///< Minimum level (atomic r/w).
    bool                            also_print_;     ///< Mirror to stderr?
    bool                            initialised_;    ///< Guard against double-init.

    /// FIFO queue of pending log entries.
    /// Protected by queue_mutex_. The writer thread blocks on queue_cv_ when
    /// the queue is empty, conserving CPU cycles.
    std::queue<LogEntry>            log_queue_;
    std::mutex                      queue_mutex_;
    std::condition_variable         queue_cv_;

    /// Set to true by shutdown() to tell the writer thread to drain and exit.
    std::atomic<bool>               shutdown_requested_;

    /// The dedicated writer thread.
    std::thread                     writer_thread_;
};


// =============================================================================
// SECTION 3: Convenience Logging Macros
// =============================================================================
//
// WHY macros for logging?
//   We need to capture __FILE__ and __LINE__ at the CALL SITE, not inside
//   a helper function. This is only possible with macros (or C++20 std::source_location,
//   which we provide as an alternative below).
//   The if(level >= min_level_) short-circuit ensures that disabled log levels
//   cost almost nothing — just an atomic load and branch.
//
// WHY use an ostringstream rather than printf-style?
//   Type safety. printf("%d", some_string) is UB. operator<< is fully type-safe.
//   For C++20 projects, replace with std::format for printf-like ergonomics
//   with type safety.

#define SAFELINK_LOG(level, component, ...)                                       \
    do {                                                                           \
        if (static_cast<uint8_t>(level) >=                                        \
            static_cast<uint8_t>(SafeLink::Logger::instance().get_level())) {     \
            std::ostringstream _sl_oss;                                            \
            _sl_oss << __VA_ARGS__;                                                \
            SafeLink::Logger::instance().log(                                      \
                level, component, _sl_oss.str(), __FILE__, __LINE__);             \
        }                                                                          \
    } while (false)
// WHY do { ... } while(false)?
//   It makes the macro a single statement. Without it, a dangling else can
//   attach to an inner if-statement inside the macro expansion rather than
//   the outer if in the caller's code.

/// Shorthand macros for each severity level.
/// The component parameter is a string literal identifying the subsystem.
#define LOG_TRACE(component, ...)   SAFELINK_LOG(SafeLink::LogLevel::TRACE,   component, __VA_ARGS__)
#define LOG_DEBUG(component, ...)   SAFELINK_LOG(SafeLink::LogLevel::DEBUG,   component, __VA_ARGS__)
#define LOG_INFO(component, ...)    SAFELINK_LOG(SafeLink::LogLevel::INFO,    component, __VA_ARGS__)
#define LOG_WARNING(component, ...) SAFELINK_LOG(SafeLink::LogLevel::WARNING, component, __VA_ARGS__)
#define LOG_ERROR(component, ...)   SAFELINK_LOG(SafeLink::LogLevel::ERROR,   component, __VA_ARGS__)
#define LOG_FATAL(component, ...)   SAFELINK_LOG(SafeLink::LogLevel::FATAL,   component, __VA_ARGS__)

// =============================================================================
// SECTION 4: Hex-Dump Helper (for cryptographic buffer inspection in TRACE logs)
// =============================================================================

/// Format a byte buffer as a space-separated hex string for TRACE logging.
/// Example: hex_dump({0xDE,0xAD,0xBE,0xEF}) → "de ad be ef"
///
/// WHY inline in the header? It is a template instantiated at the call site;
/// putting the definition in .cpp would require explicit instantiations.
inline std::string hex_dump(const uint8_t* data, size_t length) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 3);
    for (size_t i = 0; i < length; ++i) {
        result += HEX[(data[i] >> 4) & 0x0F];
        result += HEX[data[i] & 0x0F];
        if (i + 1 < length) result += ' ';
    }
    return result;
}

/// Overload for std::vector<uint8_t>.
inline std::string hex_dump(const std::vector<uint8_t>& buf) {
    return hex_dump(buf.data(), buf.size());
}

} // namespace SafeLink
