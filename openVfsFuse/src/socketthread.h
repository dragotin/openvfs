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

#ifndef _THREAD_STD_H
#define _THREAD_STD_H

// @see https://www.codeproject.com/Articles/1169105/Cplusplus-std-thread-Event-Loop-with-Message-Queue
// David Lafreniere, Feb 2017.

#include <thread>
#include <queue>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <string>
#include <future>

struct MsgData
{
    std::string msg;
    std::string file;
    std::string fileId;
    int id;
    std::string requester;
};

class SharedMap;
struct ThreadMsg;

class SocketThread
{
public:
    /// Constructor
    SocketThread(const std::string& threadName, SharedMap &map);

    /// Destructor
    ~SocketThread();

    /// Called once to create the worker thread
    /// @return True if thread is created. False otherwise. 
    bool CreateThread();

    /// Called once a program exit to exit the worker thread
    void ExitThread();

    /// Get the ID of this thread instance
    /// @return The worker thread ID
    std::thread::id GetThreadId();

    /// Get the ID of the currently executing thread
    /// @return The current thread ID
    static std::thread::id GetCurrentThreadId();

    /// Add a message to the thread queue
    /// @param[in] data - thread specific message information
    void PostMsg(std::shared_ptr<MsgData> msg);

    /// Get size of thread message queue.
    size_t GetQueueSize();

    /// Get thread name
    std::string GetThreadName() { return THREAD_NAME; }


private:
    SocketThread(const SocketThread&) = delete;
    SocketThread& operator=(const SocketThread&) = delete;

    /// Initialise the socket to communicate with the client
    int initSocket();

    bool socketSendMsg(std::shared_ptr<MsgData>);
    std::string readSocket();
    void handleReceivedMsg(const std::string& msg);

    /// Entry point for the worker thread
    void Process();

    /// Entry point for timer thread
    void TimerThread();

    void SetThreadName(std::thread::native_handle_type handle, const std::string& name);

    std::unique_ptr<std::thread> m_thread;
    std::queue<std::shared_ptr<ThreadMsg>> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_timerExit;
    const std::string THREAD_NAME;

    // Promise and future to synchronize thread start
    std::promise<void> m_threadStartPromise;
    std::future<void> m_threadStartFuture;

    std::atomic<bool> m_exit;

    const std::string _socketPath{"/run/user/1000/OpenCloud/socket"};
    std::atomic<int> _socket;

    SharedMap& _sharedMap;
};

#endif 

