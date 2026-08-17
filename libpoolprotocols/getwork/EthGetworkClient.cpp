#include "EthGetworkClient.h"

#include <chrono>
#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <libcrypto/ethash.hpp>

using namespace std;
using namespace dev;
using namespace eth;

using boost::asio::ip::tcp;

EthGetworkClient::EthGetworkClient(int worktimeout, unsigned farmRecheckPeriod)
  : PoolClient(),
    m_farmRecheckPeriod(farmRecheckPeriod),
    m_io_strand(g_io_service),
    m_socket(g_io_service),
    m_resolver(g_io_service),
    m_endpoints(),
    m_getwork_timer(g_io_service),
    m_read_timer(g_io_service),
    m_worktimeout(worktimeout)
{
    m_jSwBuilder.settings_["indentation"] = "";
    m_jsonGetWork = makeGetWork(false);
}

EthGetworkClient::~EthGetworkClient()
{
    m_getwork_timer.cancel();
    m_read_timer.cancel();
    close_socket();
    m_txQueue.consume_all([](std::string* l) { delete l; });
}

std::string EthGetworkClient::header_safe(std::string const& value)
{
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value)
    {
        if (c == '\r' || c == '\n' || c == '\0')
            continue;
        out.push_back(static_cast<char>(c));
    }
    return out;
}

std::string EthGetworkClient::makeGetWork(bool longpoll)
{
    Json::Value jGetWork;
    jGetWork["id"] = unsigned(1);
    jGetWork["jsonrpc"] = "2.0";
    jGetWork["method"] = "getblocktemplate";
    if (longpoll && !m_longpollId.empty())
    {
        Json::Value params(Json::arrayValue);
        Json::Value obj(Json::objectValue);
        obj["longpollid"] = m_longpollId;
        params.append(obj);
        jGetWork["params"] = params;
    }
    else
    {
        jGetWork["params"] = Json::Value(Json::arrayValue);
    }
    return std::string(Json::writeString(m_jSwBuilder, jGetWork));
}

void EthGetworkClient::scheduleGetWork(bool longpoll)
{
    send(makeGetWork(longpoll && m_useLongpoll.load(std::memory_order_relaxed) && !m_longpollId.empty()));
}

void EthGetworkClient::close_socket()
{
    boost::system::error_code ec;
    m_read_timer.cancel();
    if (m_socket.is_open())
    {
        m_socket.shutdown(tcp::socket::shutdown_both, ec);
        m_socket.close(ec);
    }
}

void EthGetworkClient::drop_endpoint()
{
    if (!m_endpoints.empty())
        m_endpoints.pop();
}

void EthGetworkClient::interrupt_longpoll()
{
    g_io_service.post(m_io_strand.wrap([this]() {
        if (!m_longpollInFlight.load(std::memory_order_relaxed))
            return;
        close_socket();
    }));
}

void EthGetworkClient::arm_read_timeout(bool longpoll)
{
    // Short polls should fail fast; longpoll may block until the tip moves (proxy: 300s).
    const int secs = longpoll ? 315 : 30;
    m_read_timer.expires_from_now(boost::posix_time::seconds(secs));
    m_read_timer.async_wait(
        m_io_strand.wrap(boost::bind(&EthGetworkClient::read_timer_elapsed, this, boost::asio::placeholders::error)));
}

void EthGetworkClient::read_timer_elapsed(const boost::system::error_code& ec)
{
    if (ec)
        return;
    cwarn << "RPC read timeout from " << (m_conn ? m_conn->Host() : string("?")) << ":"
          << (m_conn ? toString(m_conn->Port()) : string("?"));
    close_socket();
}

void EthGetworkClient::connect()
{
    if (!m_conn)
        return;

    // Build authentication
    m_base64_auth.clear();
    if (m_conn->User().size() || m_conn->Pass().size())
    {
        std::string authentication{m_conn->User() + ":" + m_conn->Pass()};
        size_t encoded_len{boost::beast::detail::base64::encoded_size(authentication.length())};
        m_base64_auth.resize(encoded_len, '\0');
        boost::beast::detail::base64::encode(m_base64_auth.data(), authentication.data(), authentication.length());
    }

    // Prevent unnecessary and potentially dangerous recursion
    bool expected = false;
    if (!m_connecting.compare_exchange_weak(expected, true, memory_order::memory_order_relaxed))
        return;

    // Reset status flags
    m_getwork_timer.cancel();
    m_read_timer.cancel();
    m_useLongpoll.store(true, std::memory_order_relaxed);

    // Initialize a new queue of end points
    m_endpoints = std::queue<boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>>();
    m_endpoint = boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>();

    if (m_conn->HostNameType() == dev::UriHostNameType::Dns || m_conn->HostNameType() == dev::UriHostNameType::Basic)
    {
        // Begin resolve all ips associated to hostname
        // calling the resolver each time is useful as most
        // load balancers will give Ips in different order
        m_resolver = boost::asio::ip::tcp::resolver(g_io_service);
        boost::asio::ip::tcp::resolver::query q(m_conn->Host(), toString(m_conn->Port()));

        // Start resolving async
        m_resolver.async_resolve(q, m_io_strand.wrap(boost::bind(&EthGetworkClient::handle_resolve, this,
                                        boost::asio::placeholders::error, boost::asio::placeholders::iterator)));
    }
    else
    {
        // No need to use the resolver if host is already an IP address
        m_endpoints.push(
            boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(m_conn->Host()), m_conn->Port()));
        send(m_jsonGetWork);
    }
}

void EthGetworkClient::disconnect()
{
    // Idempotent: failed first-connect used to SIGSEGV here (m_session / m_conn null).
    bool was_connecting = m_connecting.exchange(false, std::memory_order_relaxed);
    bool was_connected = m_connected.exchange(false, std::memory_order_relaxed);

    m_getwork_timer.cancel();
    m_read_timer.cancel();
    m_longpollInFlight.store(false, std::memory_order_relaxed);
    m_txPending.store(false, std::memory_order_relaxed);
    m_submitInFlight.store(false, std::memory_order_relaxed);
    close_socket();

    if (m_session && m_conn)
        m_conn->addDuration(m_session->duration());
    m_session = nullptr;

    m_txQueue.consume_all([](std::string* l) { delete l; });
    m_request.consume(m_request.capacity());
    m_response.consume(m_response.capacity());
    m_longpollId.clear();

    if ((was_connecting || was_connected) && m_onDisconnected)
        m_onDisconnected();
}

void EthGetworkClient::begin_connect()
{
    if (!m_endpoints.empty())
    {
        // Pick the first endpoint in list.
        // Eventually endpoints get discarded on connection errors
        m_endpoint = m_endpoints.front();
        m_socket.async_connect(m_endpoint, m_io_strand.wrap(boost::bind(&EthGetworkClient::handle_connect, this, _1)));
    }
    else
    {
        if (m_conn)
            cwarn << "No more IP addresses to try for host: " << m_conn->Host();
        disconnect();
    }
}

void EthGetworkClient::handle_connect(const boost::system::error_code& ec)
{
    if (!ec && m_socket.is_open())
    {
        // If in "connecting" phase raise the proper event
        if (m_connecting.load(std::memory_order_relaxed))
        {
            // Initialize new session
            m_connected.store(true, memory_order_relaxed);
            m_session = unique_ptr<Session>(new Session);
            m_session->subscribed.store(true, memory_order_relaxed);
            m_session->authorized.store(true, memory_order_relaxed);

            m_connecting.store(false, std::memory_order_relaxed);

            if (m_onConnected)
                m_onConnected();
            m_current_tstamp = std::chrono::steady_clock::now();
        }

        // Retrieve 1st line waiting in the queue and submit
        // if other lines waiting they will be processed
        // at the end of the processed request
        Json::Reader jRdr;
        std::string* line;
        std::ostream os(&m_request);
        if (!m_txQueue.empty())
        {
            while (m_txQueue.pop(line))
            {
                if (line->size())
                {
                    jRdr.parse(*line, m_pendingJReq);
                    m_pending_tstamp = std::chrono::steady_clock::now();

                    bool is_longpoll = m_pendingJReq.isMember("params") && m_pendingJReq["params"].isArray() &&
                                       m_pendingJReq["params"].size() > 0 && m_pendingJReq["params"][0].isObject() &&
                                       m_pendingJReq["params"][0].isMember("longpollid");
                    m_longpollInFlight.store(is_longpoll, std::memory_order_relaxed);

                    string _path = header_safe(m_conn && !m_conn->Path().empty() ? m_conn->Path() : "/");
                    if (_path.empty() || _path[0] != '/')
                        _path = "/" + _path;
                    string _host = header_safe(m_conn ? m_conn->Host() : "");

                    os << "POST " << _path << " HTTP/1.0\r\n";
                    os << "Host: " << _host << "\r\n";
                    os << "Content-Type: application/json\r\n";
                    os << "Content-Length: " << line->length() << "\r\n";
                    if (m_base64_auth.size())
                    {
                        os << "Authorization: Basic " << m_base64_auth << "\r\n";
                    }
                    os << "Connection: close\r\n\r\n";  // Double line feed to mark the
                                                        // beginning of body
                    // The payload
                    os << *line;

                    // Out received message only for debug purpouses
                    if (g_logOptions & LOG_JSON)
                    {
                        cnote << " >> " << *line;
                    }

                    delete line;

                    async_write(m_socket, m_request,
                        m_io_strand.wrap(
                            boost::bind(&EthGetworkClient::handle_write, this, boost::asio::placeholders::error)));
                    break;
                }
                delete line;
            }
        }
        else
        {
            m_txPending.store(false, std::memory_order_relaxed);
        }
    }
    else
    {
        if (ec != boost::asio::error::operation_aborted)
        {
            close_socket();
            if (m_conn)
                cwarn << "Error connecting to " << m_conn->Host() << ":" << toString(m_conn->Port()) << " : "
                      << ec.message();
            drop_endpoint();
            begin_connect();
        }
    }
}

void EthGetworkClient::handle_write(const boost::system::error_code& ec)
{
    if (!ec)
    {
        bool longpoll = m_longpollInFlight.load(std::memory_order_relaxed);
        arm_read_timeout(longpoll);
        async_read(m_socket, m_response,
            [this](const boost::system::error_code& err, std::size_t bytes) -> std::size_t {
                if (err)
                    return 0;
                if (bytes >= kMaxHttpResponse)
                    return 0;
                return std::size_t(4096);
            },
            m_io_strand.wrap(boost::bind(&EthGetworkClient::handle_read, this, boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred)));
    }
    else
    {
        if (ec != boost::asio::error::operation_aborted)
        {
            close_socket();
            m_longpollInFlight.store(false, std::memory_order_relaxed);
            if (m_conn)
                cwarn << "Error writing to " << m_conn->Host() << ":" << toString(m_conn->Port()) << " : "
                      << ec.message();
            drop_endpoint();
            begin_connect();
        }
    }
}

void EthGetworkClient::handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    m_read_timer.cancel();
    const bool was_longpoll = m_longpollInFlight.exchange(false, std::memory_order_relaxed);

    if (ec == boost::asio::error::operation_aborted)
    {
        close_socket();
        if (!m_txQueue.empty())
            begin_connect();
        else
            m_txPending.store(false, std::memory_order_relaxed);
        return;
    }

    if (!ec || (ec == boost::asio::error::eof && bytes_transferred > 0))
    {
        if (bytes_transferred >= kMaxHttpResponse)
        {
            cwarn << "HTTP response exceeded " << kMaxHttpResponse << " bytes from "
                  << (m_conn ? m_conn->Host() : string("?"));
            disconnect();
            return;
        }

        // Close socket
        close_socket();

        // Get the whole message
        std::string rx_message(boost::asio::buffer_cast<const char*>(m_response.data()), bytes_transferred);
        m_response.consume(bytes_transferred);

        // Empty response ?
        if (!rx_message.size())
        {
            if (m_conn)
                cwarn << "Invalid response from " << m_conn->Host() << ":" << toString(m_conn->Port());
            disconnect();
            return;
        }

        // Read message by lines.
        // First line is http status
        // Other lines are headers
        // A double "\r\n" identifies begin of body
        // The rest is body
        bool has_payload{false};
        uint32_t http_status_code{0};
        std::string line;
        std::string linedelimiter = "\r\n";
        std::size_t delimiteroffset = rx_message.find(linedelimiter);

        unsigned int linenum = 0;
        bool isHeader = true;
        while (rx_message.length() && delimiteroffset != std::string::npos)
        {
            linenum++;
            line = rx_message.substr(0, delimiteroffset);
            rx_message.erase(0, delimiteroffset + 2);

            // This identifies the beginning of body
            if (line.empty())
            {
                isHeader = false;
                delimiteroffset = rx_message.find(linedelimiter);
                if (delimiteroffset != std::string::npos)
                {
                    continue;
                }
                boost::replace_all(rx_message, "\n", "");
                line = rx_message;
            }

            // Http status
            if (isHeader && linenum == 1)
            {
                if (line.substr(0, 7) != "HTTP/1.")
                {
                    if (m_conn)
                        cwarn << "Invalid response from " << m_conn->Host() << ":" << toString(m_conn->Port());
                    disconnect();
                    return;
                }
                std::size_t spaceoffset = line.find(' ');
                if (spaceoffset == std::string::npos)
                {
                    if (m_conn)
                        cwarn << "Invalid response from " << m_conn->Host() << ":" << toString(m_conn->Port());
                    disconnect();
                    return;
                }
                std::string status = line.substr(spaceoffset + 1).substr(0, 3);
                try
                {
                    http_status_code = static_cast<uint32_t>(std::stoul(status));
                }
                catch (const std::exception&)
                {
                    if (m_conn)
                        cwarn << "Invalid HTTP status from " << m_conn->Host() << ":" << toString(m_conn->Port());
                    disconnect();
                    return;
                }
            }

            // Body
            if (!isHeader)
            {
                has_payload = true;
                // Out received message only for debug purpouses
                if (g_logOptions & LOG_JSON)
                    cnote << " << " << line;

                // Test validity of chunk and process
                Json::Value jRes;
                Json::Reader jRdr;
                if (jRdr.parse(line, jRes))
                {
                    // Run in sync so no 2 different async reads may overlap
                    processResponse(jRes);
                }
                else
                {
                    string what = jRdr.getFormattedErrorMessages();
                    boost::replace_all(what, "\n", " ");
                    cwarn << "Got invalid Json message : " << what;
                }
            }

            delimiteroffset = rx_message.find(linedelimiter);
        }

        if (!has_payload && http_status_code != 200)
        {
            if (m_conn)
                cwarn << m_conn->Host() << ":" << toString(m_conn->Port()) << " reported status " << http_status_code;
            disconnect();
            return;
        }

        // Is there anything else in the queue
        if (!m_txQueue.empty())
        {
            begin_connect();
        }
        else
        {
            // Signal end of async send/receive operations
            m_txPending.store(false, std::memory_order_relaxed);
        }
    }
    else
    {
        close_socket();
        if (m_conn)
            cwarn << "Error reading from :" << m_conn->Host() << ":" << toString(m_conn->Port()) << " : "
                  << ec.message() << " Bytes transferred " << bytes_transferred;
        if (!m_txQueue.empty())
        {
            begin_connect();
            return;
        }
        if (was_longpoll)
        {
            // Longpoll interrupted or dropped: resume with a short poll, don't tear the session down.
            m_txPending.store(false, std::memory_order_relaxed);
            scheduleGetWork(false);
            return;
        }
        disconnect();
    }
}

void EthGetworkClient::handle_resolve(const boost::system::error_code& ec, tcp::resolver::iterator i)
{
    if (!ec)
    {
        while (i != tcp::resolver::iterator())
        {
            m_endpoints.push(i->endpoint());
            i++;
        }
        m_resolver.cancel();

        // Resolver has finished so invoke connection asynchronously
        send(m_jsonGetWork);
    }
    else
    {
        if (m_conn)
            cwarn << "Could not resolve host " << m_conn->Host() << ", " << ec.message();
        disconnect();
    }
}

void EthGetworkClient::processResponse(Json::Value& JRes)
{
    unsigned _id = 0;         // This SHOULD be the same id as the request it is responding to
    bool _isSuccess = false;  // Whether or not this is a succesful or failed response
    string _errReason = "";   // Content of the error reason

    if (!JRes.isMember("id"))
    {
        if (m_conn)
            cwarn << "Missing id member in response from " << m_conn->Host() << ":" << toString(m_conn->Port());
        return;
    }
    // We get the id from pending jrequest
    // It's not guaranteed we get response labelled with same id
    // For instance Dwarfpool always responds with "id":0
    _id = m_pendingJReq.get("id", unsigned(0)).asUInt();
    _isSuccess = JRes.get("error", Json::Value::null).empty();
    _errReason = (_isSuccess ? "" : processError(JRes));

    bool pending_longpoll = m_pendingJReq.isMember("params") && m_pendingJReq["params"].isArray() &&
                            m_pendingJReq["params"].size() > 0 && m_pendingJReq["params"][0].isObject() &&
                            m_pendingJReq["params"][0].isMember("longpollid");

    // We have only theese possible ids
    // 0 or 1 as job notification
    // 9 as response for eth_submitHashrate
    // 40+ for responses to mining submissions
    if (_id == 0 || _id == 1)
    {
        // Getwork might respond with an error to
        // a request. (eg. node is still syncing)
        // In such case delay further requests
        // by 30 seconds.
        // Otherwise resubmit another getwork request
        // with a delay of m_farmRecheckPeriod ms.
        if (!_isSuccess)
        {
            if (m_conn)
                cwarn << "Got " << _errReason << " from " << m_conn->Host() << ":" << toString(m_conn->Port());
            unsigned delay_ms = pending_longpoll ? m_farmRecheckPeriod : 30000;
            std::string err_l = _errReason;
            boost::algorithm::to_lower(err_l);
            if (err_l.find("timeout") != std::string::npos || err_l.find("upstream") != std::string::npos)
                delay_ms = m_farmRecheckPeriod;
            m_getwork_timer.expires_from_now(boost::posix_time::milliseconds(delay_ms));
            m_getwork_timer.async_wait(m_io_strand.wrap(
                boost::bind(&EthGetworkClient::getwork_timer_elapsed, this, boost::asio::placeholders::error)));
            return;
        }

        auto schedule_next = [this](bool longpoll_now) {
            if (longpoll_now && m_useLongpoll.load(std::memory_order_relaxed) && !m_longpollId.empty())
            {
                scheduleGetWork(true);
            }
            else
            {
                m_getwork_timer.expires_from_now(boost::posix_time::milliseconds(m_farmRecheckPeriod));
                m_getwork_timer.async_wait(m_io_strand.wrap(
                    boost::bind(&EthGetworkClient::getwork_timer_elapsed, this, boost::asio::placeholders::error)));
            }
        };

        if (!JRes.isMember("result") || !JRes["result"].isObject())
        {
            if (m_conn)
                cwarn << "Missing result data for getblocktemplate request from " << m_conn->Host() << ":"
                      << toString(m_conn->Port());
            schedule_next(false);
            return;
        }

        Json::Value JPrm = JRes.get("result", Json::Value::null);

        if (JPrm.isMember("longpollid") && JPrm["longpollid"].isString())
        {
            std::string lp = JPrm["longpollid"].asString();
            if (!lp.empty() && lp.find_first_of("\r\n") == std::string::npos)
                m_longpollId = lp;
        }

        // Sanity checks
        if (!JPrm.isMember("pprpcheader") || !JPrm.isMember("pprpcepoch") || !JPrm.isMember("height") ||
            !JPrm.isMember("bits") || !JPrm.isMember("target"))
        {
            if (m_conn)
                cwarn << "Invalid/incomplete work package info from " << m_conn->Host() << ":"
                      << toString(m_conn->Port());
            schedule_next(false);
            return;
        }

        try
        {
            WorkPackage newWp;

            newWp.header = h256(JPrm["pprpcheader"].asString());
            newWp.epoch = strtoul(JPrm["pprpcepoch"].asString().c_str(), nullptr, 0);
            auto seed = ethash::calculate_seed_from_epoch(newWp.epoch.value());
            newWp.seed = h256(seed.bytes, dev::h256::ConstructFromPointer);

            // Compute block boundary from bits
            uint32_t bits = std::strtoul(JPrm["bits"].asString().c_str(), nullptr, 16);
            auto block_target = ethash::from_compact(bits);
            newWp.block_boundary = h256(block_target.bytes, dev::h256::ConstructFromPointer);

            newWp.boundary = h256(JPrm["target"].asString());
            newWp.block = strtoul(JPrm["height"].asString().c_str(), nullptr, 0);
            newWp.job = newWp.header.hex();

            const bool header_changed = (m_current.header != newWp.header);
            if (header_changed)
            {
                m_current = newWp;
                m_current_tstamp = std::chrono::steady_clock::now();

                if (m_onWorkReceived)
                    m_onWorkReceived(m_current);
            }

            // If longpoll returns immediately with the same job, the server is ignoring longpollid.
            if (pending_longpoll && !header_changed)
            {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - m_pending_tstamp);
                if (elapsed.count() < 750)
                {
                    cnote << "GBT longpoll returned immediately; falling back to "
                          << m_farmRecheckPeriod << " ms polling";
                    m_useLongpoll.store(false, std::memory_order_relaxed);
                    schedule_next(false);
                    return;
                }
            }
            else if (!pending_longpoll && !m_longpollId.empty() &&
                     m_useLongpoll.load(std::memory_order_relaxed))
            {
                cnote << "GBT longpoll armed";
            }
        }
        catch (const std::exception& ex)
        {
            cwarn << "Bad work package from " << (m_conn ? m_conn->Host() : string("?")) << " : " << ex.what();
            schedule_next(false);
            return;
        }

        schedule_next(true);
    }
    else if (_id == 9)
    {
        // Response to hashrate submission
        // Actually don't do anything
    }
    else if (_id >= 40 && _id <= m_solution_submitted_max_id)
    {
        if (_isSuccess && JRes["result"].isConvertibleTo(Json::ValueType::booleanValue))
            _isSuccess = JRes["result"].asBool();

        std::chrono::milliseconds _delay =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - m_pending_tstamp);

        const unsigned miner_index = _id - 40;
        m_submitInFlight.store(false, std::memory_order_relaxed);

        if (_isSuccess)
        {
            if (m_onSolutionAccepted)
                m_onSolutionAccepted(_delay, miner_index, false);
            // Tip advanced (or should have). Prefer an immediate short GBT so the
            // next job is not delayed behind a longpoll wait / solution flood.
            interrupt_longpoll();
            m_longpollId.clear();
            scheduleGetWork(false);
        }
        else
        {
            if (m_onSolutionRejected)
                m_onSolutionRejected(_delay, miner_index);
            // Rejected seals often leave the tip unchanged. Longpoll would block
            // until a tip change that never comes (e.g. bad-auxpow-missing on a
            // poisoned Meraki template). Force a short-poll GBT for a fresh job.
            interrupt_longpoll();
            m_longpollId.clear();
            scheduleGetWork(false);
        }
    }
}

std::string EthGetworkClient::processError(Json::Value& JRes)
{
    std::string retVar;

    if (JRes.isMember("error") && !JRes.get("error", Json::Value::null).isNull())
    {
        if (JRes["error"].isConvertibleTo(Json::ValueType::stringValue))
        {
            retVar = JRes.get("error", "Unknown error").asString();
        }
        else if (JRes["error"].isConvertibleTo(Json::ValueType::arrayValue))
        {
            for (auto i : JRes["error"])
            {
                retVar += i.asString() + " ";
            }
        }
        else if (JRes["error"].isConvertibleTo(Json::ValueType::objectValue))
        {
            for (Json::Value::iterator i = JRes["error"].begin(); i != JRes["error"].end(); ++i)
            {
                Json::Value k = i.key();
                Json::Value v = (*i);
                retVar += (std::string)i.name() + ":" + v.asString() + " ";
            }
        }
    }
    else
    {
        retVar = "Unknown error";
    }

    return retVar;
}

void EthGetworkClient::send(Json::Value const& jReq)
{
    send(std::string(Json::writeString(m_jSwBuilder, jReq)));
}

void EthGetworkClient::send(std::string const& sReq)
{
    std::string* line = new std::string(sReq);
    m_txQueue.push(line);

    bool ex = false;
    if (m_txPending.compare_exchange_weak(ex, true, std::memory_order_relaxed))
        begin_connect();
    else if (m_longpollInFlight.load(std::memory_order_relaxed))
        interrupt_longpoll();
}

void EthGetworkClient::submitHashrate(uint64_t const& rate, string const& id)
{
    // Just return as the node does not support it
    (void)rate;
    (void)id;
    return;
}

bool EthGetworkClient::submitSolution(const Solution& solution)
{
    if (!m_session)
        return false;

    // Drop extras while a seal is outstanding. Easy TestNet targets otherwise
    // enqueue millions of pprpcsb calls and starve getblocktemplate refresh.
    bool expected = false;
    if (!m_submitInFlight.compare_exchange_strong(expected, true, std::memory_order_relaxed))
        return false;

    Json::Value jReq;
    string nonceHex = toHex(solution.nonce, dev::HexPrefix::Add);

    unsigned id = 40 + solution.midx;
    jReq["id"] = id;
    jReq["jsonrpc"] = "2.0";
    m_solution_submitted_max_id = max(m_solution_submitted_max_id, id);
    jReq["method"] = "pprpcsb";
    jReq["params"] = Json::Value(Json::arrayValue);
    jReq["params"].append(solution.work.header.hex());  // Don't prepend 0x (evrprogpow has a dictionary of hashes)
    jReq["params"].append(solution.mixHash.hex());
    jReq["params"].append(nonceHex);
    send(jReq);
    return true;
}

void EthGetworkClient::getwork_timer_elapsed(const boost::system::error_code& ec)
{
    // Triggers the resubmission of a getWork request
    if (!ec)
    {
        // Check if last work is older than timeout
        std::chrono::seconds _delay =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - m_current_tstamp);
        if (m_worktimeout > 0 && _delay.count() > m_worktimeout)
        {
            cwarn << "No new work received in " << m_worktimeout << " seconds.";
            disconnect();
        }
        else
        {
            scheduleGetWork(false);
        }
    }
}
