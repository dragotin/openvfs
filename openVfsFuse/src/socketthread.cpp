/*
 * openvfsfuse - a Fuse layer to handle virtual filesystem items of cloud storage
 * Copyright (C) 2025  Klaas Freitag <k.freitag@opencloud.eu>
 *
 * Original code of this file:
 * Copyright (c) 2022 David Lafreniere, licensed under MIT License
 * (See LICENSE file in 3rdparty dir)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "socketthread.h"
#include "json.hpp"
#include "sharedmap.h"
#include "strtools.h"

#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


using namespace std;

#define MSG_EXIT_THREAD 1
#define MSG_POST_USER_DATA 2
#define MSG_TIMER 3

using json = nlohmann::json;

struct ThreadMsg
{
    ThreadMsg(int i, std::shared_ptr<void> m)
    {
        id = i;
        msg = m;
    }
    int id;
    std::shared_ptr<void> msg;
};

//----------------------------------------------------------------------------
// SocketThread
//----------------------------------------------------------------------------
SocketThread::SocketThread(const std::string &threadName, SharedMap &map)
    : m_thread(nullptr)
    , m_exit(false)
    , m_timerExit(false)
    , THREAD_NAME(threadName)
    , _sharedMap(map)
{
}

//----------------------------------------------------------------------------
// ~SocketThread
//----------------------------------------------------------------------------
SocketThread::~SocketThread()
{
    ExitThread();
}

//----------------------------------------------------------------------------
// CreateThread
//----------------------------------------------------------------------------
bool SocketThread::CreateThread()
{
    if (!m_thread) {
        m_threadStartFuture = m_threadStartPromise.get_future();

        m_thread = std::unique_ptr<std::thread>(new thread(&SocketThread::Process, this));

        auto handle = m_thread->native_handle();
        SetThreadName(handle, THREAD_NAME);

        // Wait for the thread to enter the Process method
        m_threadStartFuture.get();

        initSocket();
    }

    return true;
}

int SocketThread::initSocket()
{
    _socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_socket < 0) {
        return -1;
    }
    // Put the socket in non-blocking mode:
    if (fcntl(_socket, F_SETFL, fcntl(_socket, F_GETFL) | O_NONBLOCK) < 0) {
        // handle error
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, _socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    /* send  a welcome message to the SocketAPI */
    std::shared_ptr<MsgData> msgData(new MsgData());
    msgData->msg = "VERSION";
    PostMsg(msgData);

    return 1;
}

bool SocketThread::socketSendMsg(std::shared_ptr<MsgData> msgData)
{
    std::string msg{msgData->msg};

    // prepare the OpenCloud message to be sent over the wire
    if (msg.empty()) {
        return false;
    }

    const json j = {
        {"id", std::to_string(msgData->id)}, {"arguments", {{"file", msgData->file}, {"fileId", msgData->fileId}, {"requster", msgData->requester}}}};

    msg += ":";
    msg += j.dump();
    msg += '\n';

    cout << "Raw message: " << msg << endl;
    // send message
    unsigned long int value;

    value = write(_socket, msg.c_str(), msg.size());
    if (value < 0) {
        perror("write");
        close(_socket);
        return false;
    }

    std::cout << "Sent message: " << msg << std::endl;
    return true;
    // openvfsfuse_log(socket_path.c_str(), "socket send", value, "Message: %s", msg.c_str());
}

std::string SocketThread::readSocket()
{
    // read answer FIXME: Split messages by \n and keep the rest
    char buf[1024];
    ssize_t n = read(_socket, buf, sizeof(buf) - 1);
    if (n <= 0)
        return std::string();
    return std::string(buf, n);
}

void SocketThread::handleReceivedMsg(const std::string &rawmsg)
{
    if (rawmsg.empty()) {
        cout << "Received Message empty" << endl;
        return;
    }

    auto copies = StrTools::split(rawmsg, 0x000A);

    for (const string &msg : copies) {
        string msgType, msgAttr;
        if (msg.empty()) {
            continue;
        }

        cout << "Handle single message " << msg << endl;

        size_t found = msg.find(':');
        if (found != string::npos) {
            msgType = msg.substr(0, found);
            msgAttr = msg.substr(found + 1, string::npos);
        }

        // FIXME: Think if splitting by newline makes sense

        if (msgType == "V2/HYDRATE_FILE_RESULT") {
            const auto j = json::parse(msgAttr);
            const int id = std::stoi(j["id"].get<string>());

            const auto status = j["arguments"]["status"].get<string>();

            // rename this file to final dest.

            if (id > 0) {
                int res{-1}; // Default set to fail
                if (status == "OK") {
                    res = 0; // good!
                } else {
                    cout << "ERROR from socket API for Id" << id << endl;
                }

                const HydJob hj{.state = res};
                bool ok = _sharedMap.set(id, hj);
                if (!ok) {
                    // the id could not be set. That means, the job was not inserted.
                    cout << "Job not found:" << id << endl;
                } else {
                    cout << "Setting Job ID " << id << " to result " << res << endl;
                }
            }
        } else if (msgType == "VERSION") {
            vector<string> attribs = StrTools::split(msgAttr, ':');
            if (attribs.size() == 3) {
                cout << "Got PID of the Desktop Client: " << attribs.at(2) << endl;
                _sharedMap.setDesktopClientPid(std::stol(attribs.at(2)));
            }
        }
    }
}


//----------------------------------------------------------------------------
// GetThreadId
//----------------------------------------------------------------------------
std::thread::id SocketThread::GetThreadId()
{
    assert(m_thread);
    return m_thread->get_id();
}

//----------------------------------------------------------------------------
// GetCurrentThreadId
//----------------------------------------------------------------------------
std::thread::id SocketThread::GetCurrentThreadId()
{
    return this_thread::get_id();
}

//----------------------------------------------------------------------------
// GetQueueSize
//----------------------------------------------------------------------------
size_t SocketThread::GetQueueSize()
{
    lock_guard<mutex> lock(m_mutex);
    return m_queue.size();
}

//----------------------------------------------------------------------------
// SetThreadName
//----------------------------------------------------------------------------
void SocketThread::SetThreadName(std::thread::native_handle_type handle, const std::string &name)
{
#ifdef WIN32
    // Set the thread name so it shows in the Visual Studio Debug Location toolbar
    std::wstring wstr(name.begin(), name.end());
    HRESULT hr = SetThreadDescription(handle, wstr.c_str());
    if (FAILED(hr)) {
        // Handle error if needed
    }
#endif
}

//----------------------------------------------------------------------------
// ExitThread
//----------------------------------------------------------------------------
void SocketThread::ExitThread()
{
    if (!m_thread)
        return;

    // Create a new ThreadMsg
    std::shared_ptr<ThreadMsg> threadMsg(new ThreadMsg(MSG_EXIT_THREAD, 0));

    // Put exit thread message into the queue
    {
        lock_guard<mutex> lock(m_mutex);
        m_queue.push(threadMsg);
        m_cv.notify_one();
    }

    m_exit.store(true);
    m_thread->join();

    // Clear the queue if anything added while waiting for join
    {
        lock_guard<mutex> lock(m_mutex);
        m_thread = nullptr;
        while (!m_queue.empty())
            m_queue.pop();
    }
}

//----------------------------------------------------------------------------
// PostMsg
//----------------------------------------------------------------------------
void SocketThread::PostMsg(std::shared_ptr<MsgData> data)
{
    if (m_exit.load())
        return;
    assert(m_thread);

    // Create a new ThreadMsg
    std::shared_ptr<ThreadMsg> threadMsg(new ThreadMsg(MSG_POST_USER_DATA, data));

    // Add user data msg to queue and notify worker thread
    std::unique_lock<std::mutex> lk(m_mutex);
    m_queue.push(threadMsg);
    m_cv.notify_one();
}

//----------------------------------------------------------------------------
// TimerThread
//----------------------------------------------------------------------------
void SocketThread::TimerThread()
{
    while (!m_timerExit) {
        // Sleep for 250mS then put a MSG_TIMER into the message queue
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::shared_ptr<ThreadMsg> threadMsg(new ThreadMsg(MSG_TIMER, 0));

        // Add timer msg to queue and notify worker thread
        std::unique_lock<std::mutex> lk(m_mutex);
        m_queue.push(threadMsg);
        m_cv.notify_one();
    }
}

//----------------------------------------------------------------------------
// Process
//----------------------------------------------------------------------------
void SocketThread::Process()
{
    // Signal that the thread has started processing to notify CreateThread
    m_threadStartPromise.set_value();

    m_timerExit = false;
    std::thread timerThread(&SocketThread::TimerThread, this);

    while (1) {
        std::shared_ptr<ThreadMsg> msg;
        {
            // Wait for a message to be added to the queue
            std::unique_lock<std::mutex> lk(m_mutex);
            while (m_queue.empty())
                m_cv.wait(lk);

            if (m_queue.empty())
                continue;

            msg = m_queue.front();
            m_queue.pop();
        }

        // The msg->id is an Id to identify the kind of thread msg. It is
        // not the transfer id of the client job
        switch (msg->id) {
        case MSG_POST_USER_DATA: {
            if (msg->msg) {
                std::cout << "Received user data message" << std::endl;
            }
            assert(msg->msg);

            auto msgData = std::static_pointer_cast<MsgData>(msg->msg);
            cout << "Sending " << msgData->id << ": " << msgData->msg << " " << msgData->file << " on " << THREAD_NAME << endl;

            if (!socketSendMsg(msgData)) {
                cout << "Failed to send msg " << msgData->id << ": " << msgData->msg.c_str() << endl;
            } else {
                if (msgData->id > 0) {
                    const HydJob hj{.state = 1};
                    _sharedMap.insert(msgData->id, hj);
                    cout << "Storing sent message ID" << msgData->id << endl;
                }
            }
            break;
        }

        case MSG_TIMER: {
            // cout << "Timer expired on " << THREAD_NAME << endl;
            const std::string msg = readSocket();
            if (!msg.empty()) {
                cout << "Message received: " << msg << endl;
                handleReceivedMsg(msg);
            }
            break;
        }

        case MSG_EXIT_THREAD: {
            m_timerExit = true;
            // if (msgData->id > 0) {
            //     _sharedMap.insert(msgData->id, 2);
            // }
            timerThread.join();
            return;
        }

        default:
            assert(false);
        }
    }
    std::cout << "SocketThread exiting" << std::endl;
}
