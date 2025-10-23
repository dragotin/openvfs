![License MIT](https://img.shields.io/github/license/BehaviorTree/BehaviorTree.CPP?color=blue)
[![conan Ubuntu](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_ubuntu.yml/badge.svg)](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_ubuntu.yml)
[![conan Ubuntu](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_clang.yml/badge.svg)](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_clang.yml)
[![conan Windows](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_windows.yml/badge.svg)](https://github.com/endurodave/StdWorkerThread/actions/workflows/cmake_windows.yml)

# C++ std::thread Event Loop with Message Queue and Timer

Create a worker thread with an event loop, message queue and a timer using the C++11 thread support library.

# Table of Contents

- [C++ std::thread Event Loop with Message Queue and Timer](#c-stdthread-event-loop-with-message-queue-and-timer)
- [Table of Contents](#table-of-contents)
- [Preface](#preface)
- [Getting Started](#getting-started)
- [Introduction](#introduction)
- [Background](#background)
- [WorkerThread](#workerthread)
- [Event Loop](#event-loop)
  - [Event Loop (Win32)](#event-loop-win32)
- [Timer](#timer)
- [Usage](#usage)
- [Related Repositories](#related-repositories)
- [Conclusion](#conclusion)

# Preface

Originally published on CodeProject at: <a href="http://www.codeproject.com/Articles/1169105/Cplusplus-std-thread-Event-Loop-with-Message-Queue"><strong>C++ std::thread Event Loop with Message Queue and Timer</strong></a>

# Getting Started

[CMake](https://cmake.org/) is used to create the project build files on any Windows or Linux machine. The source code works on any C++ compiler with `std::thread` support.

1. Clone the repository.
2. From the repository root, run the following CMake command:   
   `cmake -B Build .`
3. Build and run the project within the `Build` directory. 

# Introduction

<p>An event loop, or sometimes called a message loop, is a thread that waits for and dispatches incoming events. The thread blocks waiting for requests to arrive and then dispatches the event to an event handler function. A message queue is typically used by the loop to hold incoming messages. Each message is sequentially dequeued, decoded, and then an action is performed. Event loops are one way to implement inter-process communication.</p>

<p>All operating systems provide support for multi-threaded applications. Each OS has unique function calls for creating threads, message queues and timers. With the advent of the C++11 thread support library, it&rsquo;s now possible to create portable code and avoid the OS-specific function calls. This article provides a simple example of how to create a thread event loop, message queue and timer services while only relying upon the C++ Standard Library. Any C++11 compiler supporting the thread library should be able to compile the attached source.</p>

# Background

<p>Typically, I need a thread to operate as an event loop. Incoming messages are dequeued by the thread and data is dispatched to an appropriate function handler based on a unique message identifier. Timer support capable of invoking a function is handy for low speed polling or to generate a timeout if something doesn&rsquo;t happen in the expected amount of time. Many times, the worker thread is created at startup and isn&rsquo;t destroyed until the application terminates.</p>

<p>A key requirement for the implementation is that the incoming messages must execute on the same thread instance. Whereas say <code>std::async </code>may use a temporary thread from a pool, this class ensures that all incoming messages use the same thread. For instance, a subsystem could be implemented with code that is not thread-safe. A single <code>WorkerThread </code>instance is used to safely dispatch function calls into the subsystem.</p>

<p>At first glance, the C++ thread support seems to be missing some key features. Yes, <code>std::thread </code>is available to spin off a thread but there is no thread-safe queue and no timers &ndash; services that most OS&rsquo;s provide. I&rsquo;ll show how to use the C++ Standard Library to create these &ldquo;missing&rdquo; features and provide an event processing loop familiar to many programmers.</p>

# WorkerThread

<p>The <code>WorkerThread </code>class encapsulates all the necessary event loop mechanisms. A simple class interface allows thread creation, posting messages to the event loop, and eventual thread termination. The interface is shown below:</p>

<pre lang="C++">
class WorkerThread
{
public:
&nbsp; &nbsp; /// Constructor
&nbsp; &nbsp; WorkerThread(const char* threadName);

&nbsp; &nbsp; /// Destructor
&nbsp; &nbsp; ~WorkerThread();

&nbsp; &nbsp; /// Called once to create the worker thread
&nbsp; &nbsp; /// @return True if thread is created. False otherwise.&nbsp;
&nbsp; &nbsp; bool CreateThread();

&nbsp; &nbsp; /// Called once a program exit to exit the worker thread
&nbsp; &nbsp; void ExitThread();

&nbsp; &nbsp; /// Get the ID of this thread instance
&nbsp; &nbsp; /// @return The worker thread ID
&nbsp; &nbsp; std::thread::id GetThreadId();

&nbsp; &nbsp; /// Get the ID of the currently executing thread
&nbsp; &nbsp; /// @return The current thread ID
&nbsp; &nbsp; static std::thread::id GetCurrentThreadId();

&nbsp; &nbsp; /// Add a message to the thread queue
&nbsp; &nbsp; /// @param[in] data - thread specific message information
&nbsp; &nbsp; void PostMsg(std::shared_ptr&lt;UserData&gt; msg);

private:
&nbsp; &nbsp; WorkerThread(const WorkerThread&amp;) = delete;
&nbsp; &nbsp; WorkerThread&amp; operator=(const WorkerThread&amp;) = delete;

&nbsp; &nbsp; /// Entry point for the worker thread
&nbsp; &nbsp; void Process();

&nbsp; &nbsp; /// Entry point for timer thread
&nbsp; &nbsp; void TimerThread();

&nbsp; &nbsp; std::unique_ptr&lt;std::thread&gt; m_thread;
&nbsp; &nbsp; std::queue&lt;std::shared_ptr&lt;ThreadMsg&gt;&gt; m_queue;
&nbsp; &nbsp; std::mutex m_mutex;
&nbsp; &nbsp; std::condition_variable m_cv;
&nbsp; &nbsp; std::atomic&lt;bool&gt; m_timerExit;
&nbsp; &nbsp; const char* THREAD_NAME;
};</pre>

<p>The first thing to notice is that <code>std::thread </code>is used to create a main worker thread. The main worker thread function is <code>Process()</code>.</p>

<pre lang="C++">
bool WorkerThread::CreateThread()
{
    if (!m_thread)
        m_thread = new thread(&amp;WorkerThread::Process, this);
    return true;
}</pre>

# Event Loop

<p>The <code>Process() </code>event loop is shown below. The thread relies upon a <code>std::queue&lt;ThreadMsg*&gt; </code>for the message queue. <code>std::queue </code>is not thread-safe so all access to the queue must be protected by mutex. A <code>std::condition_variable </code>is used to suspend the thread until notified that a new message has been added to the queue.</p>

<pre lang="C++">
void WorkerThread::Process()
{
&nbsp; &nbsp; m_timerExit = false;
&nbsp; &nbsp; std::thread timerThread(&amp;WorkerThread::TimerThread, this);

&nbsp;&nbsp; &nbsp;while (1)
&nbsp;&nbsp; &nbsp;{
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;std::shared_ptr&lt;ThreadMsg&gt; msg;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;{
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;// Wait for a message to be added to the queue
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;std::unique_lock&lt;std::mutex&gt; lk(m_mutex);
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;while (m_queue.empty())
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;m_cv.wait(lk);

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;if (m_queue.empty())
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;continue;

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;msg = m_queue.front();
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;m_queue.pop();
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;}

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;switch (msg-&gt;id)
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;{
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;case MSG_POST_USER_DATA:
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;{
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;ASSERT_TRUE(msg-&gt;msg != NULL);

&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; auto userData = std::static_pointer_cast&lt;UserData&gt;(msg-&gt;msg);
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; cout &lt;&lt; userData-&gt;msg.c_str() &lt;&lt; &quot; &quot; &lt;&lt; userData-&gt;year &lt;&lt; &quot; on &quot; &lt;&lt; THREAD_NAME &lt;&lt; endl;

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;break;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;}

&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; case MSG_TIMER:
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; cout &lt;&lt; &quot;Timer expired on &quot; &lt;&lt; THREAD_NAME &lt;&lt; endl;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; break;

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;case MSG_EXIT_THREAD:
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;{
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; m_timerExit = true;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; timerThread.join();
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; return;
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;}

&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;default:
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;ASSERT();
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;}
&nbsp;&nbsp; &nbsp;}
}</pre>

<p><code>PostMsg() </code>creates a new <code>ThreadMsg </code>on the heap, adds the message to the queue, and then notifies the worker thread using a condition variable.</p>

<pre lang="C++">
void WorkerThread::PostMsg(std::shared_ptr&lt;UserData&gt; data)
{
&nbsp;&nbsp; &nbsp;ASSERT_TRUE(m_thread);

&nbsp;&nbsp; &nbsp;// Create a new ThreadMsg
&nbsp; &nbsp; std::shared_ptr&lt;ThreadMsg&gt; threadMsg(new ThreadMsg(MSG_POST_USER_DATA, data));

&nbsp;&nbsp; &nbsp;// Add user data msg to queue and notify worker thread
&nbsp;&nbsp; &nbsp;std::unique_lock&lt;std::mutex&gt; lk(m_mutex);
&nbsp;&nbsp; &nbsp;m_queue.push(threadMsg);
&nbsp;&nbsp; &nbsp;m_cv.notify_one();
}</pre>

<p>The loop will continue to process messages until the <code>MSG_EXIT_THREAD </code>is received and the thread exits.</p>

<pre lang="C++">
void WorkerThread::ExitThread()
{
&nbsp;&nbsp; &nbsp;if (!m_thread)
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;return;

&nbsp;&nbsp; &nbsp;// Create a new ThreadMsg
&nbsp;&nbsp; &nbsp;std::shared_ptr&lt;ThreadMsg&gt; threadMsg(new ThreadMsg(MSG_EXIT_THREAD, 0));

&nbsp;&nbsp; &nbsp;// Put exit thread message into the queue
&nbsp;&nbsp; &nbsp;{
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;lock_guard&lt;mutex&gt; lock(m_mutex);
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;m_queue.push(threadMsg);
&nbsp;&nbsp; &nbsp;&nbsp;&nbsp; &nbsp;m_cv.notify_one();
&nbsp;&nbsp; &nbsp;}

&nbsp; &nbsp; m_thread-&gt;join();
&nbsp; &nbsp; m_thread = nullptr;
}</pre>

## Event Loop (Win32)

<p>The code snippet below contrasts the <code>std::thread </code>event loop above with a similar Win32 version using the Windows API. Notice <code>GetMessage() </code>API is used in lieu of the <code>std::queue</code>. Messages are posted to the OS message queue using <code>PostThreadMessage()</code>. And finally, <code>timerSetEvent() </code>is used to place <code>WM_USER_TIMER </code>messages into the queue. All of these services are provided by the OS. The <code>std::thread WorkerThread </code>implementation presented here avoids the raw OS calls yet the implementation functionality is the same as the Win32 version while relying only upon only the C++ Standard Library.</p>

<pre lang="C++">
unsigned long WorkerThread::Process(void* parameter)
{
    MSG msg;
    BOOL bRet;

    // Start periodic timer
    MMRESULT timerId = timeSetEvent(250, 10, &amp;WorkerThread::TimerExpired, 
                       reinterpret_cast&lt;DWORD&gt;(this), TIME_PERIODIC);

    while ((bRet = GetMessage(&amp;msg, NULL, WM_USER_BEGIN, WM_USER_END)) != 0)
    {
        switch (msg.message)
        {
            case WM_DISPATCH_DELEGATE:
            {
                ASSERT_TRUE(msg.wParam != NULL);

                // Convert the ThreadMsg void* data back to a UserData*
                const UserData* userData = static_cast&lt;const UserData*&gt;(msg.wParam);

                cout &lt;&lt; userData-&gt;msg.c_str() &lt;&lt; &quot; &quot; &lt;&lt; userData-&gt;year &lt;&lt; &quot; on &quot; &lt;&lt; THREAD_NAME &lt;&lt; endl;

                // Delete dynamic data passed through message queue
                delete userData;
                break;
            }

            case WM_USER_TIMER:
                cout &lt;&lt; &quot;Timer expired on &quot; &lt;&lt; THREAD_NAME &lt;&lt; endl;
                break;

            case WM_EXIT_THREAD:
                timeKillEvent(timerId);
                return 0;

            default:
                ASSERT();
        }
    }
    return 0;
}</pre>

# Timer

<p>A low-resolution periodic timer message is inserted into the queue using a secondary private thread. The timer thread is created inside <code>Process()</code>.</p>

<pre lang="C++">
void WorkerThread::Process()
{
    m_timerExit = false;
    std::thread timerThread(&amp;WorkerThread::TimerThread, this);

...</pre>

<p>The timer thread&rsquo;s sole responsibility is to insert a <code>MSG_TIMER </code>message every 250ms. In this implementation, there&rsquo;s no protection against the timer thread injecting more than one timer message into the queue. This could happen if the worker thread falls behind and can&rsquo;t service the message queue fast enough. Depending on the worker thread, processing load, and how fast the timer messages are inserted, additional logic could be employed to prevent flooding the queue.</p>

<pre lang="C++">
void WorkerThread::TimerThread()
{
&nbsp; &nbsp; while (!m_timerExit)
&nbsp; &nbsp; {
&nbsp; &nbsp; &nbsp; &nbsp; // Sleep for 250mS then put a MSG_TIMER into the message queue
&nbsp; &nbsp; &nbsp; &nbsp; std::this_thread::sleep_for(250ms);

&nbsp; &nbsp; &nbsp; &nbsp; std::shared_ptr&lt;ThreadMsg&gt; threadMsg (new ThreadMsg(MSG_TIMER, 0));

&nbsp; &nbsp; &nbsp; &nbsp; // Add timer msg to queue and notify worker thread
&nbsp; &nbsp; &nbsp; &nbsp; std::unique_lock&lt;std::mutex&gt; lk(m_mutex);
&nbsp; &nbsp; &nbsp; &nbsp; m_queue.push(threadMsg);
&nbsp; &nbsp; &nbsp; &nbsp; m_cv.notify_one();
&nbsp; &nbsp; }
}</pre>

# Usage

<p>The <code>main()</code> function below shows how to use the <code>WorkerThread </code>class. Two worker threads are created and a message is posted to each one. After a short delay, both threads exit.</p>

<pre lang="C++">
// Worker thread instances
WorkerThread workerThread1(&quot;WorkerThread1&quot;);
WorkerThread workerThread2(&quot;WorkerThread2&quot;);

int main(void)
{&nbsp;&nbsp; &nbsp;
&nbsp;&nbsp; &nbsp;// Create worker threads
&nbsp;&nbsp; &nbsp;workerThread1.CreateThread();
&nbsp;&nbsp; &nbsp;workerThread2.CreateThread();

&nbsp;&nbsp; &nbsp;// Create message to send to worker thread 1
&nbsp;&nbsp; &nbsp;std::shared_ptr&lt;UserData&gt; userData1(new UserData());
&nbsp;&nbsp; &nbsp;userData1-&gt;msg = &quot;Hello world&quot;;
&nbsp;&nbsp; &nbsp;userData1-&gt;year = 2017;

&nbsp;&nbsp; &nbsp;// Post the message to worker thread 1
&nbsp;&nbsp; &nbsp;workerThread1.PostMsg(userData1);

&nbsp;&nbsp; &nbsp;// Create message to send to worker thread 2
&nbsp;&nbsp; &nbsp;std::shared_ptr&lt;UserData&gt; userData2(new UserData());
&nbsp;&nbsp; &nbsp;userData2-&gt;msg = &quot;Goodbye world&quot;;
&nbsp;&nbsp; &nbsp;userData2-&gt;year = 2017;

&nbsp;&nbsp; &nbsp;// Post the message to worker thread 2
&nbsp;&nbsp; &nbsp;workerThread2.PostMsg(userData2);

&nbsp;&nbsp; &nbsp;// Give time for messages processing on worker threads
&nbsp;&nbsp; &nbsp;this_thread::sleep_for(1s);

&nbsp;&nbsp; &nbsp;workerThread1.ExitThread();
&nbsp;&nbsp; &nbsp;workerThread2.ExitThread();

&nbsp;&nbsp; &nbsp;return 0;
}</pre>

# Related Repositories

Real-world projects using `WorkerThread`.

* <a href="https://github.com/endurodave/DelegateMQ">Asynchronous Delegates in C++</a> - Invoke any C++ callable function synchronously, asynchronously, or on a remote endpoint.
* <a href="https://github.com/endurodave/StateMachineWithThreads">C++ State Machine with Threads</a> - A framework combining C++ state machines and multicast asynchronous callbacks.
* <a href="https://github.com/endurodave/StateMachineWithModernDelegates">C++ State Machine with Asynchronous Delegates</a> - A framework combining C++ state machines and asynchronous delegate callbacks.
* <a href="https://github.com/endurodave/AsyncStateMachine">Asynchronous State Machine Design in C++</a> - An asynchronous C++ state machine implemented using an asynchronous delegate library.
* <a href="https://github.com/endurodave/IntegrationTestFramework">Integration Test Framework using Google Test and Delegates</a> - A multi-threaded C++ software integration test framework using Google Test and DelegateMQ libraries.
* <a href="https://github.com/endurodave/Async-SQLite">Asynchronous SQLite API using C++ Delegates</a> - An asynchronous SQLite wrapper implemented using an asynchronous delegate library.

# Conclusion

<p>The C++ thread support library offers a platform independent way to write multi-threaded application code without reliance upon OS-specific API&rsquo;s. The <code>WorkerThread </code>class presented here is a bare-bones implementation of an event loop, yet all the basics are there ready to be expanded upon.</p>

