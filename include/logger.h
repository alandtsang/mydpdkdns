#ifndef INCLUDE_LOGGER_H_
#define INCLUDE_LOGGER_H_

#include <string>
#include <memory> 
#include <cstdarg>

#include <spdlog/spdlog.h>

#define LOG_BUFFER_SIZE 1024
#define FILL_BUFFER  char buffer[LOG_BUFFER_SIZE]; \
    va_list args; \
    va_start(args, fmt); \
    vsnprintf(buffer, LOG_BUFFER_SIZE, fmt, args); \
    va_end(args);


namespace dnslog {

struct log_info {
    std::string domain;
    std::vector<std::string> xcdn;
    std::string sip;
    std::string country;
    std::string prov;
    std::string isp;
    std::string city;
};

class Logger {
public:
    static std::shared_ptr<Logger> getLogger();
    ~Logger() { }

    inline void set_level(int level) {
        switch (level) {
            case 2:
                spdlog::set_level(spdlog::level::info);
                enabled = true;
                break;
            case 6:
            default:
                spdlog::set_level(spdlog::level::off);
                enabled = false;
                break;
        }
    }

    inline void log_info(const char* fmt, ...) {
        FILL_BUFFER
        spdlog_->info(buffer);
    }

    void log_info(std::string& domain, std::string& xcdn,
        std::string& sip, std::string& country, std::string& prov,
        std::string& isp, std::string& city);

    inline void log_err(const char* fmt, ...) {
        FILL_BUFFER
        spdlog_->error(buffer);
    }

    bool enabled;

private:
    Logger() {
        spdlog::set_async_mode(1048576);
        spdlog_ = spdlog::hourly_logger_mt("file_logger", "../log/log");
        spdlog_->set_pattern("[%Y-%m-%d %T] %v");
    }

    std::string topic_;
    std::string msg_;

    static std::shared_ptr<Logger> logger_;
    std::shared_ptr<spdlog::logger> spdlog_;
};

}  // namespace dnslog

#endif  /* INCLUDE_LOGGER_H_ */

