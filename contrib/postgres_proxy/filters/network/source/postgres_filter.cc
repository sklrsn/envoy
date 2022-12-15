#include "contrib/postgres_proxy/filters/network/source/postgres_filter.h"

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/common/assert.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "contrib/postgres_proxy/filters/network/source/postgres_decoder.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace PostgresProxy {

PostgresFilterConfig::PostgresFilterConfig(const PostgresFilterConfigOptions& config_options,
                                           Stats::Scope& scope)
    : enable_sql_parsing_(config_options.enable_sql_parsing_),
      terminate_ssl_(config_options.terminate_ssl_), upstream_ssl_(config_options.upstream_ssl_),
      scope_{scope}, stats_{generateStats(config_options.stats_prefix_, scope)},
      db_name_(config_options.db_name_), db_username_(config_options.db_username_),
      db_password_(config_options.db_password_) {}

PostgresFilter::PostgresFilter(PostgresFilterConfigSharedPtr config) : config_{config} {
  if (!decoder_) {
    decoder_ = createDecoder(this);
  }
}

// Network::ReadFilter
Network::FilterStatus PostgresFilter::onData(Buffer::Instance& data, bool) {
  ENVOY_CONN_LOG(trace, "postgres_proxy: got {} bytes", read_callbacks_->connection(),
                 data.length());

  // Frontend Buffer
  frontend_buffer_.add(data);
  Network::FilterStatus result = doDecode(frontend_buffer_, true);
  if (result == Network::FilterStatus::StopIteration) {
    ASSERT(frontend_buffer_.length() == 0);
    data.drain(data.length());
  }
  return result;
}

Network::FilterStatus PostgresFilter::onNewConnection() { return Network::FilterStatus::Continue; }

void PostgresFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

// Network::WriteFilter
Network::FilterStatus PostgresFilter::onWrite(Buffer::Instance& data, bool) {

  // Backend Buffer
  backend_buffer_.add(data);
  Network::FilterStatus result = doDecode(backend_buffer_, false);
  if (result == Network::FilterStatus::StopIteration) {
    ASSERT(backend_buffer_.length() == 0);
    data.drain(data.length());
  }
  return result;
}

DecoderPtr PostgresFilter::createDecoder(DecoderCallbacks* callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
}

void PostgresFilter::incMessagesBackend() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_backend_.inc();
}

void PostgresFilter::incMessagesFrontend() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_frontend_.inc();
}

void PostgresFilter::incMessagesUnknown() {
  config_->stats_.messages_.inc();
  config_->stats_.messages_unknown_.inc();
}

void PostgresFilter::incSessionsEncrypted() {
  config_->stats_.sessions_.inc();
  config_->stats_.sessions_encrypted_.inc();
}

void PostgresFilter::incSessionsUnencrypted() {
  config_->stats_.sessions_.inc();
  config_->stats_.sessions_unencrypted_.inc();
}

void PostgresFilter::incTransactions() {
  if (!decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_.inc();
  }
}

void PostgresFilter::incTransactionsCommit() {
  if (!decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_commit_.inc();
  }
}

void PostgresFilter::incTransactionsRollback() {
  if (decoder_->getSession().inTransaction()) {
    config_->stats_.transactions_rollback_.inc();
  }
}

void PostgresFilter::incNotices(NoticeType type) {
  config_->stats_.notices_.inc();
  switch (type) {
  case DecoderCallbacks::NoticeType::Warning:
    config_->stats_.notices_warning_.inc();
    break;
  case DecoderCallbacks::NoticeType::Notice:
    config_->stats_.notices_notice_.inc();
    break;
  case DecoderCallbacks::NoticeType::Debug:
    config_->stats_.notices_debug_.inc();
    break;
  case DecoderCallbacks::NoticeType::Info:
    config_->stats_.notices_info_.inc();
    break;
  case DecoderCallbacks::NoticeType::Log:
    config_->stats_.notices_log_.inc();
    break;
  case DecoderCallbacks::NoticeType::Unknown:
    config_->stats_.notices_unknown_.inc();
    break;
  }
}

void PostgresFilter::incErrors(ErrorType type) {
  config_->stats_.errors_.inc();
  switch (type) {
  case DecoderCallbacks::ErrorType::Error:
    config_->stats_.errors_error_.inc();
    break;
  case DecoderCallbacks::ErrorType::Fatal:
    config_->stats_.errors_fatal_.inc();
    break;
  case DecoderCallbacks::ErrorType::Panic:
    config_->stats_.errors_panic_.inc();
    break;
  case DecoderCallbacks::ErrorType::Unknown:
    config_->stats_.errors_unknown_.inc();
    break;
  }
}

void PostgresFilter::incStatements(StatementType type) {
  config_->stats_.statements_.inc();

  switch (type) {
  case DecoderCallbacks::StatementType::Insert:
    config_->stats_.statements_insert_.inc();
    break;
  case DecoderCallbacks::StatementType::Delete:
    config_->stats_.statements_delete_.inc();
    break;
  case DecoderCallbacks::StatementType::Select:
    config_->stats_.statements_select_.inc();
    break;
  case DecoderCallbacks::StatementType::Update:
    config_->stats_.statements_update_.inc();
    break;
  case DecoderCallbacks::StatementType::Other:
    config_->stats_.statements_other_.inc();
    break;
  case DecoderCallbacks::StatementType::Noop:
    break;
  }
}

void PostgresFilter::processQuery(const std::string& sql) {
  if (config_->enable_sql_parsing_) {
    ProtobufWkt::Struct metadata;

    auto result = Common::SQLUtils::SQLUtils::setMetadata(sql, decoder_->getAttributes(), metadata);

    if (!result) {
      config_->stats_.statements_parse_error_.inc();
      ENVOY_CONN_LOG(trace, "postgres_proxy: cannot parse SQL: {}", read_callbacks_->connection(),
                     sql.c_str());
      return;
    }

    config_->stats_.statements_parsed_.inc();
    ENVOY_CONN_LOG(trace, "postgres_proxy: query processed {}", read_callbacks_->connection(),
                   sql.c_str());

    // Set dynamic metadata
    read_callbacks_->connection().streamInfo().setDynamicMetadata(
        NetworkFilterNames::get().PostgresProxy, metadata);
  }
}

std::string PostgresFilter::getDatabaseName() { return config_->db_name_; }
std::string PostgresFilter::getDatabaseUser() { return config_->db_username_; }
std::string PostgresFilter::getDatabasePassword() { return config_->db_password_; }

void PostgresFilter::onStartupRequest(Buffer::Instance& data) {
  // send startup message to upstream
  std::string _message = data.toString();
  ENVOY_LOG(trace, "on startup request:{}", _message);

  /*
  auto _attributes = absl::StrSplit(_message.substr(4), absl::ByChar('\0'), absl::SkipEmpty());

  Buffer::OwnedImpl buf;
  buf.add("user");
  buf.add(config_->db_username_);
  buf.add("database");
  buf.add(config_->db_name_);

  if (_attributes.find("application_name") != _attributes.end()) {
  buf.add("application_name");
  buf.add(_attributes["application_name"]);
  }
  if (_attributes.find("encoding") != _attributes.end()) {
    buf.add("encoding");
    buf.add(_attributes["encoding"])
  }
  */

  read_callbacks_->connection().addBytesSentCallback([=](uint64_t bytes) -> void {
    ENVOY_CONN_LOG(trace, "postgres_proxy: forwarded startup message to upstream",
                   read_callbacks_->connection());
    ENVOY_LOG(trace, "transferred message:{}", bytes);
  });
  
  read_callbacks_->connection().write(data, false);
}

bool PostgresFilter::onClearTextPasswordRequest() {
  Buffer::OwnedImpl buf;
  buf.add("p");
  buf.add(config_->db_password_);

  read_callbacks_->connection().addBytesSentCallback([=](uint64_t bytes) -> bool {
    ENVOY_CONN_LOG(trace, "postgres_proxy: forwarded startup message to upstream",
                   read_callbacks_->connection());
    ENVOY_LOG(trace, "transferred message:{}", bytes);
    return true;
  });
  read_callbacks_->connection().write(buf, false);

  return false;
}

bool PostgresFilter::onAuthenticationMD5Password() {
  ENVOY_LOG(trace, "NOT IMPLEMENTED");
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
  return false;
}

bool PostgresFilter::onAuthenticationKerberosV5() {
  ENVOY_LOG(trace, "NOT IMPLEMENTED");
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
  return false;
}

bool PostgresFilter::onSSLRequest() {
  if (!config_->terminate_ssl_) {
    // Signal to the decoder to continue.
    return true;
  }
  // Send single bytes 'S' to indicate switch to TLS.
  // Refer to official documentation for protocol details:
  // https://www.postgresql.org/docs/current/protocol-flow.html
  Buffer::OwnedImpl buf;
  buf.add("S");
  // Add callback to be notified when the reply message has been
  // transmitted.
  read_callbacks_->connection().addBytesSentCallback([=](uint64_t bytes) -> bool {
    // Wait until 'S' has been transmitted.
    if (bytes >= 1) {
      if (!read_callbacks_->connection().startSecureTransport()) {
        ENVOY_CONN_LOG(
            info, "postgres_proxy: cannot enable downstream secure transport. Check configuration.",
            read_callbacks_->connection());
        read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
      } else {
        // Unsubscribe the callback.
        config_->stats_.sessions_terminated_ssl_.inc();
        ENVOY_CONN_LOG(trace, "postgres_proxy: enabled SSL termination.",
                       read_callbacks_->connection());
        // Switch to TLS has been completed.
        // Signal to the decoder to stop processing the current message (SSLRequest).
        // Because Envoy terminates SSL, the message was consumed and should not be
        // passed to other filters in the chain.
        return false;
      }
    }
    return true;
  });
  read_callbacks_->connection().write(buf, false);

  return false;
}

bool PostgresFilter::shouldEncryptUpstream() const {
  return (config_->upstream_ssl_ ==
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::REQUIRE);
}

void PostgresFilter::sendUpstream(Buffer::Instance& data) {
  read_callbacks_->injectReadDataToFilterChain(data, false);
}

void PostgresFilter::encryptUpstream(bool upstream_agreed, Buffer::Instance& data) {
  RELEASE_ASSERT(
      config_->upstream_ssl_ !=
          envoy::extensions::filters::network::postgres_proxy::v3alpha::PostgresProxy::DISABLE,
      "encryptUpstream should not be called when upstream SSL is disabled.");
  if (!upstream_agreed) {
    ENVOY_CONN_LOG(info,
                   "postgres_proxy: upstream server rejected request to establish SSL connection. "
                   "Terminating.",
                   read_callbacks_->connection());
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);

    config_->stats_.sessions_upstream_ssl_failed_.inc();
  } else {
    // Try to switch upstream connection to use a secure channel.
    if (read_callbacks_->startUpstreamSecureTransport()) {
      config_->stats_.sessions_upstream_ssl_success_.inc();
      read_callbacks_->injectReadDataToFilterChain(data, false);
      ENVOY_CONN_LOG(trace, "postgres_proxy: upstream SSL enabled.", read_callbacks_->connection());
    } else {
      ENVOY_CONN_LOG(info,
                     "postgres_proxy: cannot enable upstream secure transport. Check "
                     "configuration. Terminating.",
                     read_callbacks_->connection());
      read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
      config_->stats_.sessions_upstream_ssl_failed_.inc();
    }
  }
}

Network::FilterStatus PostgresFilter::doDecode(Buffer::Instance& data, bool frontend) {
  // Keep processing data until buffer is empty or decoder says
  // that it cannot process data in the buffer.
  while (0 < data.length()) {
    switch (decoder_->onData(data, frontend)) {
    case Decoder::Result::NeedMoreData:
      return Network::FilterStatus::Continue;
    case Decoder::Result::ReadyForNext:
      continue;
    case Decoder::Result::Stopped:
      return Network::FilterStatus::StopIteration;
    }
  }
  return Network::FilterStatus::Continue;
}

} // namespace PostgresProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
