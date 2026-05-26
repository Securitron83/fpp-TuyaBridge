#pragma once
/*
 * TuyaLog — lightweight plugin-specific logger.
 * Appends timestamped lines to /home/fpp/media/logs/fpp-TuyaBridge.log
 * (or $FPPDIR_MEDIA/logs/fpp-TuyaBridge.log if the env var is set).
 * Thread-safe; each write opens, appends, and closes the file.
 *
 * Debug mode: create /home/fpp/media/plugins/fpp-TuyaBridge/debug.flag
 * (toggle from the Developer Tools panel in the Tuya Bridge UI).
 * TuyaLog::debug() is a no-op when the flag file is absent.
 */
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string>
#include <unistd.h>

namespace TuyaLog {

namespace detail {

inline std::mutex& mtx() {
    static std::mutex m;
    return m;
}

inline void write(const char* level, const char* fmt, va_list ap) {
    const char* media = getenv("FPPDIR_MEDIA");
    std::string path  = std::string(media ? media : "/home/fpp/media")
                        + "/logs/fpp-TuyaBridge.log";

    std::lock_guard<std::mutex> lk(mtx());
    FILE* f = fopen(path.c_str(), "a");
    if (!f) return;

    time_t now = time(nullptr);
    char   ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] [%-5s] ", ts, level);
    vfprintf(f, fmt, ap);
    fputc('\n', f);
    fclose(f);
}

} // namespace detail

// Returns true when the debug flag file exists.
// Checked on every TuyaLog::debug() call so toggling from the UI takes effect
// immediately without restarting fppd.
inline bool debugEnabled() {
    const char* media = getenv("FPPDIR_MEDIA");
    std::string flag  = std::string(media ? media : "/home/fpp/media")
                        + "/plugins/fpp-TuyaBridge/debug.flag";
    return access(flag.c_str(), F_OK) == 0;
}

inline void info(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    detail::write("INFO",  fmt, a);
    va_end(a);
}

inline void warn(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    detail::write("WARN",  fmt, a);
    va_end(a);
}

inline void err(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    detail::write("ERROR", fmt, a);
    va_end(a);
}

inline void debug(const char* fmt, ...) {
    if (!debugEnabled()) return;
    va_list a; va_start(a, fmt);
    detail::write("DEBUG", fmt, a);
    va_end(a);
}

} // namespace TuyaLog
