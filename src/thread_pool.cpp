#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();
    void   submit(std::function<void()> task);
    void   shutdown();
    size_t size() const { return workers_.size(); }
private:
    void worker_loop();
    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> task_queue_;
    std::mutex                        queue_mutex_;
    std::condition_variable           cv_;
    bool                              stop_{false};
};

// -----------------------------------------------------------------------------

ThreadPool::ThreadPool(size_t num_threads) {
    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i)
        workers_.emplace_back(&ThreadPool::worker_loop, this);
}

ThreadPool::~ThreadPool() { shutdown(); }

void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        task_queue_.push(std::move(task));
    }
    cv_.notify_one();
}

void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (stop_) return;
        stop_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_)
        if (t.joinable()) t.join();
}

void ThreadPool::worker_loop() {
    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        cv_.wait(lock, [this] { return stop_ || !task_queue_.empty(); });
        if (stop_ && task_queue_.empty()) return;
        auto task = std::move(task_queue_.front());
        task_queue_.pop();
        lock.unlock();
        task();
    }
}
