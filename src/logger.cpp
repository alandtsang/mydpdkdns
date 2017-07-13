
#include "logger.h"

namespace dnslog {

std::shared_ptr<Logger> Logger::logger_;

std::shared_ptr<Logger> Logger::getLogger() {
    if (!logger_) {
        struct make_shared_helper : public Logger{};
        logger_ = std::make_shared<make_shared_helper>();
    }
    return logger_;
}

}  // namespace dnslog
