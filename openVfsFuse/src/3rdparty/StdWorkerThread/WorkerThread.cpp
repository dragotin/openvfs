#include "WorkerThread.h"
#include "Fault.h"
#include <iostream>

#ifdef WIN32
#include <Windows.h>
#endif

using namespace std;

#define MSG_EXIT_THREAD			1
#define MSG_POST_USER_DATA		2
#define MSG_TIMER				3

struct ThreadMsg
{
	ThreadMsg(int i, std::shared_ptr<void> m) { id = i; msg = m; }
	int id;
    std::shared_ptr<void> msg;
};

//----------------------------------------------------------------------------
// WorkerThread
//----------------------------------------------------------------------------
WorkerThread::WorkerThread(const std::string& threadName) : 
	m_thread(nullptr), 
	m_exit(false), 
	m_timerExit(false), 
	THREAD_NAME(threadName)
{
}

//----------------------------------------------------------------------------
// ~WorkerThread
//----------------------------------------------------------------------------
WorkerThread::~WorkerThread()
{
	ExitThread();
}

//----------------------------------------------------------------------------
// CreateThread
//----------------------------------------------------------------------------
bool WorkerThread::CreateThread()
{
	if (!m_thread)
	{
		m_threadStartFuture = m_threadStartPromise.get_future();

		m_thread = std::unique_ptr<std::thread>(new thread(&WorkerThread::Process, this));

		auto handle = m_thread->native_handle();
		SetThreadName(handle, THREAD_NAME);

		// Wait for the thread to enter the Process method
		m_threadStartFuture.get();
	}

	return true;
}

//----------------------------------------------------------------------------
// GetThreadId
//----------------------------------------------------------------------------
std::thread::id WorkerThread::GetThreadId()
{
	ASSERT_TRUE(m_thread != nullptr);
	return m_thread->get_id();
}

//----------------------------------------------------------------------------
// GetCurrentThreadId
//----------------------------------------------------------------------------
std::thread::id WorkerThread::GetCurrentThreadId()
{
	return this_thread::get_id();
}

//----------------------------------------------------------------------------
// GetQueueSize
//----------------------------------------------------------------------------
size_t WorkerThread::GetQueueSize()
{
	lock_guard<mutex> lock(m_mutex);
	return m_queue.size();
}

//----------------------------------------------------------------------------
// SetThreadName
//----------------------------------------------------------------------------
void WorkerThread::SetThreadName(std::thread::native_handle_type handle, const std::string& name)
{
#ifdef WIN32
	// Set the thread name so it shows in the Visual Studio Debug Location toolbar
	std::wstring wstr(name.begin(), name.end());
	HRESULT hr = SetThreadDescription(handle, wstr.c_str());
	if (FAILED(hr))
	{
		// Handle error if needed
	}
#endif
}

//----------------------------------------------------------------------------
// ExitThread
//----------------------------------------------------------------------------
void WorkerThread::ExitThread()
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
void WorkerThread::PostMsg(std::shared_ptr<UserData> data)
{
	if (m_exit.load())
		return;
	ASSERT_TRUE(m_thread);

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
void WorkerThread::TimerThread()
{
    while (!m_timerExit)
    {
        // Sleep for 250mS then put a MSG_TIMER into the message queue
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::shared_ptr<ThreadMsg> threadMsg (new ThreadMsg(MSG_TIMER, 0));

        // Add timer msg to queue and notify worker thread
        std::unique_lock<std::mutex> lk(m_mutex);
        m_queue.push(threadMsg);
        m_cv.notify_one();
    }
}

//----------------------------------------------------------------------------
// Process
//----------------------------------------------------------------------------
void WorkerThread::Process()
{
	// Signal that the thread has started processing to notify CreateThread
	m_threadStartPromise.set_value();

    m_timerExit = false;
    std::thread timerThread(&WorkerThread::TimerThread, this);

	while (1)
	{
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

		switch (msg->id)
		{
			case MSG_POST_USER_DATA:
			{
				ASSERT_TRUE(msg->msg != NULL);

                auto userData = std::static_pointer_cast<UserData>(msg->msg);
                cout << userData->msg.c_str() << " " << userData->year << " on " << THREAD_NAME << endl;

				break;
			}

            case MSG_TIMER:
                cout << "Timer expired on " << THREAD_NAME << endl;
                break;

			case MSG_EXIT_THREAD:
			{
                m_timerExit = true;
                timerThread.join();
                return;
			}

			default:
				ASSERT();
		}
	}
}

