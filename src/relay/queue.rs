//! A queue to a connection, from anywhere: the events of its subscriptions,
//! and the answers to those it publishes. tokio's channels set aside room
//! for 32 of what they hold as they're made, and a connection had two,
//! mostly empty: a quiet connection's queues now hold nothing at all, and
//! give back what a burst took once it's gone.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

pub struct Queue<T> {
    state: Mutex<State<T>>,
    ready: Notify,
    /// How many pushed haven't been [handled](Self::handled) yet.
    unhandled: AtomicUsize,
}

struct State<T> {
    items: VecDeque<T>,
    /// Whether one was refused for want of room.
    overflowed: bool,
}

/// The most room a queue keeps once it's emptied.
const KEPT: usize = 64;

impl<T> Queue<T> {
    pub fn new() -> Arc<Queue<T>> {
        Arc::new(Queue {
            state: Mutex::new(State {
                items: VecDeque::new(),
                overflowed: false,
            }),
            ready: Notify::new(),
            unhandled: AtomicUsize::new(0),
        })
    }

    pub fn push(&self, item: T) {
        self.unhandled.fetch_add(1, Ordering::AcqRel);
        self.state.lock().expect("unpoisoned").items.push_back(item);
        self.ready.notify_one();
    }

    /// Push `item` if fewer than `max` wait, or else mark the queue
    /// overflowed, for [`Self::next`] to say. Returns whether it was.
    pub fn push_within(&self, item: T, max: usize) -> bool {
        let pushed = {
            let mut state = self.state.lock().expect("unpoisoned");
            match state.items.len() < max {
                true => {
                    self.unhandled.fetch_add(1, Ordering::AcqRel);
                    state.items.push_back(item);
                }
                false => state.overflowed = true,
            }
            !state.overflowed
        };
        self.ready.notify_one();
        pushed
    }

    /// Mark it overflowed, for [`Self::next`] to say.
    pub fn overflow(&self) {
        self.state.lock().expect("unpoisoned").overflowed = true;
        self.ready.notify_one();
    }

    /// Note that one popped is handled.
    pub fn handled(&self) {
        self.unhandled.fetch_sub(1, Ordering::AcqRel);
    }

    /// Whether every one pushed is handled: none is waiting, nor popped
    /// and being handled.
    pub fn all_handled(&self) -> bool {
        self.unhandled.load(Ordering::Acquire) == 0
    }

    /// The next waiting, if one is.
    pub fn pop(&self) -> Option<T> {
        let mut state = self.state.lock().expect("unpoisoned");
        let item = state.items.pop_front();
        if state.items.is_empty() && state.items.capacity() > KEPT {
            state.items = VecDeque::new();
        }
        item
    }

    /// The next, once there is one, or `None` once it's overflowed. Cancel
    /// safe.
    pub async fn next(&self) -> Option<T> {
        loop {
            if self.state.lock().expect("unpoisoned").overflowed {
                return None;
            }
            if let Some(item) = self.pop() {
                return Some(item);
            }
            // A push since the pop leaves a permit, so this returns at once.
            self.ready.notified().await;
        }
    }
}

#[cfg(test)]
impl<T> Queue<T> {
    pub fn state_overflowed(&self) -> bool {
        self.state.lock().unwrap().overflowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hands_over_in_order_and_says_when_overflowed() {
        let queue = Queue::new();
        let waiting = tokio::spawn({
            let queue = queue.clone();
            async move { (queue.next().await, queue.next().await) }
        });
        tokio::task::yield_now().await;
        queue.push(1);
        queue.push(2);
        assert_eq!(waiting.await.unwrap(), (Some(1), Some(2)));

        for n in 0..200 {
            assert!(queue.push_within(n, 200));
        }
        assert_eq!(queue.pop(), Some(0));
        assert!(queue.push_within(200, 200));
        assert!(!queue.push_within(201, 200));
        // What came before, then the overflow.
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.next().await, None);
        while queue.pop().is_some() {}
        assert_eq!(queue.state.lock().unwrap().items.capacity(), 0);
    }
}
