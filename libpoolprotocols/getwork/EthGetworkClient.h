#pragma once

#include <iostream>
#include <string>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/lockfree/queue.hpp>

#include <json/json.h>

#include "../PoolClient.h"

using namespace std;
using namespace dev;
using namespace eth;

class EthGetworkClient : public PoolClient
{
public:
    EthGetworkClient(int worktimeout, unsigned farmRecheckPeriod);
    ~EthGetworkClient();

    void connect() override;
    void disconnect() override;

    void submitHashrate(uint64_t const& rate, string const& id) override;
    // Returns true if this seal was queued for pprpcsb (false if dropped/busy).
    bool submitSolution(const Solution& solution) override;

private:
    unsigned m_farmRecheckPeriod = 250;  // In milliseconds

    void begin_connect();
    void handle_resolve(const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator i);
    void handle_connect(const boost::system::error_code& ec);
    void handle_write(const boost::system::error_code& ec);
    void handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred);
    std::string processError(Json::Value& JRes);
    void processResponse(Json::Value& JRes);
    void send(Json::Value const& jReq);
    void send(std::string const& sReq);
    void getwork_timer_elapsed(const boost::system::error_code& ec);
    void read_timer_elapsed(const boost::system::error_code& ec);
    void close_socket();
    void drop_endpoint();
    void interrupt_longpoll();
    void arm_read_timeout(bool longpoll);
    void scheduleGetWork(bool longpoll);
    std::string makeGetWork(bool longpoll);
    static std::string header_safe(std::string const& value);

    static constexpr std::size_t kMaxHttpResponse = 8 * 1024 * 1024;

    WorkPackage m_current;

    std::atomic<bool> m_connecting = {false};  // Whether or not socket is on first try connect
    std::atomic<bool> m_txPending = {false};   // Whether or not an async socket operation is pending
    std::atomic<bool> m_longpollInFlight = {false};
    std::atomic<bool> m_useLongpoll = {true};
    // Solo/easy-diff can produce millions of nonces; only one pprpcsb may be in flight
    // or the HTTP queue starves getblocktemplate and the tip never advances.
    std::atomic<bool> m_submitInFlight = {false};
    boost::lockfree::queue<std::string*> m_txQueue;

    boost::asio::io_service::strand m_io_strand;

    boost::asio::ip::tcp::socket m_socket;
    boost::asio::ip::tcp::resolver m_resolver;
    std::queue<boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>> m_endpoints;

    boost::asio::streambuf m_request;
    boost::asio::streambuf m_response;
    Json::StreamWriterBuilder m_jSwBuilder;
    std::string m_jsonGetWork;
    std::string m_longpollId;
    Json::Value m_pendingJReq;
    std::chrono::time_point<std::chrono::steady_clock> m_pending_tstamp;

    boost::asio::deadline_timer m_getwork_timer;  // The timer which triggers getWork requests
    boost::asio::deadline_timer m_read_timer;     // Caps hung HTTP reads / longpolls

    // seconds to trigger a work_timeout (overwritten in constructor)
    int m_worktimeout;
    std::chrono::time_point<std::chrono::steady_clock> m_current_tstamp;

    unsigned m_solution_submitted_max_id;  // maximum json id we used to send a solution

    std::string m_base64_auth{};  // Used by evrprogpow for http authentication;
};
