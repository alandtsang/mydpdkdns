#ifndef INCLUDE_WORKER_H_
#define INCLUDE_WORKER_H_

#include <vector>
#include "decoder.h"
#include "logger.h"


class Worker {
public:
    Worker() {
        logger = dnslog::Logger::getLogger();
    }
    ~Worker() {}

    Decoder decoder;
    std::shared_ptr<dnslog::Logger> logger;
};

#endif
