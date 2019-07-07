use super::{errno_str, Error};
use libc::*;
use spin::Mutex;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::{null, null_mut};
use std::time::Duration;

/*
 * This file is not yet used!
 *
 * Currently we are relying on epoll since lx added everything we need there and it was the
 * quickest path forward for getting boringtun to work.
 */

/// A return type for the EventPoll::wait() function
pub enum WaitResult<'a, H> {
    /// Event triggered normally
    Ok(EventGuard<'a, H>),
    /// Event triggered due to End of File conditions
    EoF(EventGuard<'a, H>),
    /// There was an error
    Error(String),
}

/// Implements a registry of pollable events
pub struct EventPoll<H: Sized> {
    events: Mutex<Vec<Option<Box<Event<H>>>>>, // Events with a file descriptor
    custom: Mutex<Vec<Option<Box<Event<H>>>>>, // Other events (i.e. timers & notifiers)
    signals: Mutex<Vec<Option<Box<Event<H>>>>>, // Signal handlers
    port: RawFd,                               // The OS event port
}

/// A type that hold a reference to a triggered Event
/// While an EventGuard exists for a given Event, it will not be triggered by any other thread
/// Once the EventGuard goes out of scope, the underlying Event will be reenabled
pub struct EventGuard<'a, H> {
    port: RawFd,
    event: &'a Event<H>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an EventPoll
pub struct EventRef {
    trigger: RawFd,
}

#[derive(PartialEq)]
enum EventKind {
    FD,
    Notifier,
    Signal,
    Timer,
}

// A single event
struct Event<H> {
    event: port_event, // The port event description
    handler: H,        // The associated data
    kind: EventKind,
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        unsafe { close(self.port) };
    }
}

impl<H: Send + Sync> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<EventPoll<H>, Error> {
        let port = match unsafe { port_create() } {
            -1 => return Err(Error::EventQueue(errno_str())),
            port => port,
        };

        Ok(EventPoll {
            events: Mutex::new(vec![]),
            custom: Mutex::new(vec![]),
            signals: Mutex::new(vec![]),
            port,
        })
    }
}
