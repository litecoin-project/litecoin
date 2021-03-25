#include <mw/common/Logger.h>

void null_logger(const std::string&) {}

static std::function<void(const std::string&)> LOGGER_CALLBACK = null_logger;
static LoggerAPI::LogLevel MIN_LOG_LEVEL = LoggerAPI::TRACE;

namespace LoggerAPI
{
    void Initialize(const std::function<void(const std::string&)>& log_callback)
    {
        if (log_callback) {
            LOGGER_CALLBACK = log_callback;
        } else {
            LOGGER_CALLBACK = null_logger;
        }
    }

    void Log(
        const LoggerAPI::LogLevel log_level,
        const std::string& function,
        const size_t line,
        const std::string& message) noexcept
    {
        if (log_level >= MIN_LOG_LEVEL) {
            std::string formatted = StringUtil::Format("{}({}) - {}", function, line, message);

            size_t newlinePos = formatted.find("\n");
            while (newlinePos != std::string::npos) {
                if (formatted.size() > newlinePos + 2) {
                    formatted.erase(newlinePos, 2);
                } else {
                    formatted.erase(newlinePos, 1);
                }

                newlinePos = formatted.find("\n");
            }

            LOGGER_CALLBACK(formatted);
        }
    }
}