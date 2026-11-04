// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard};
use std::ops::Deref;

/// A special type of read/write lock, that makes the following assumptions:
/// a) Read access is frequent, and has to be very fast, so we want to hold it indefinitely
/// b) Write access is very rare (think less than once per second) and can be a bit slower
/// c) A thread that holds a read lock, can ask for an upgrade to a write lock, cooperatively asking other threads to yield their locks
pub struct Lock<T: ?Sized> {
    wants_write: (Mutex<bool>, Condvar),
    inner: RwLock<T>, // Although parking lot lock is upgradable, it does not allow a two staged mark + lock upgrade
}

impl<T> Lock<T> {
    /// New lock
    pub fn new(user_data: T) -> Lock<T> {
        Lock {
            wants_write: (Mutex::new(false), Condvar::new()),
            inner: RwLock::new(user_data),
        }
    }
}

impl<T: ?Sized> Lock<T> {
    /// Acquire a read lock
    pub fn read(&self) -> LockReadGuard<'_, T> {
        let (lock, cvar) = &self.wants_write;
        let mut wants_write = lock.lock();
        while *wants_write {
            // We have a writer and we want to wait for it to go away
            cvar.wait(&mut wants_write);
        }

        LockReadGuard {
            wants_write: &self.wants_write,
            inner: self.inner.read(),
        }
    }
}

pub struct LockReadGuard<'a, T: 'a + ?Sized> {
    wants_write: &'a (Mutex<bool>, Condvar),
    inner: RwLockReadGuard<'a, T>,
}

// Release the writer intent even if an operation unwinds. Otherwise every
// later read (including DeviceHandle::drop) waits on a flag nobody can clear.
struct WriteIntentReset<'a>(&'a (Mutex<bool>, Condvar));
impl Drop for WriteIntentReset<'_> {
    fn drop(&mut self) {
        let (lock, cvar) = self.0;
        *lock.lock() = false;
        cvar.notify_all();
    }
}

impl<T: ?Sized> LockReadGuard<'_, T> {
    /// Perform a closure on a mutable reference of the inner locked value.
    ///
    /// # Parameters
    ///
    /// `prep_func` - A closure that will run once, after the lock marks its intention to write,
    /// this can be used to tell other threads to yield their read locks temporarily. It will be passed
    /// an immutable reference to the inner value.
    ///
    /// `mut_func` - A closure that will run once write access is gained. It iwll be passed a mutable reference
    /// to the inner value.
    ///
    pub fn try_writeable<U, P: FnOnce(&T), F: FnOnce(&mut T) -> U>(
        &mut self,
        prep_func: P,
        mut_func: F,
    ) -> Option<U> {
        // First tell everyone that we want to write now, this will prevent any new reader from starting until we are done.
        {
            let &(lock, cvar) = &self.wants_write;
            let mut wants_write = lock.lock();

            RwLockReadGuard::unlocked(&mut self.inner, move || {
                while *wants_write {
                    // We have a writer and we want to wait for it to go away
                    cvar.wait(&mut wants_write);
                }

                *wants_write = true;
            });
        }

        let reset = WriteIntentReset(self.wants_write);

        // Second stage is to run the prep function
        prep_func(&*self.inner);

        let lock = RwLockReadGuard::rwlock(&self.inner);

        // Third stage is to perform our op under a write lock
        let ret = Some(RwLockReadGuard::unlocked(&mut self.inner, move || {
            // There is no race here because wants_write blocks other threads
            let mut write_access = lock.write();
            mut_func(&mut *write_access)
        }));

        drop(reset);

        ret
    }
}

impl<T: ?Sized> Deref for LockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writer_panic_does_not_strand_readers() {
        let lock = std::sync::Arc::new(Lock::new(0));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                lock.read()
                    .try_writeable(|_| {}, |_| panic!("test operation panic"));
            }))
            .is_err()
        );
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || send.send(*lock.read()).unwrap());
        assert_eq!(
            receive
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap(),
            0
        );
    }
}
