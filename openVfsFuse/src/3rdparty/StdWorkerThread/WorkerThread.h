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

struct UserData
{
    std::string msg;
    int year;
};

struct ThreadMsg;

class WorkerThread
{
public:
    /// Constructor
    WorkerThread(const std::string& threadName);

    /// Destructor
    ~WorkerThread();

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
    void PostMsg(std::shared_ptr<UserData> msg);

    /// Get size of thread message queue.
    size_t GetQueueSize();

    /// Get thread name
    std::string GetThreadName() { return THREAD_NAME; }

private:
    WorkerThread(const WorkerThread&) = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;

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
};

#endif 

