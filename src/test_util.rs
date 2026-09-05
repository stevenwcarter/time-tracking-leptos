//! Helpers shared by more than one module's unit tests.
//!
//! `pub(crate)` rather than a private helper inside whichever test module
//! wanted it first: two copies of an executor, each with its own idea of
//! what "finished" means, is exactly the sort of thing that drifts.

use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Runs a future that is expected to finish without ever yielding.
///
/// Every async path this crate tests on the host is synchronous in
/// practice — the browser halves are compiled out, and what is left awaits
/// nothing real — so one poll is the whole executor. A future that did
/// yield would park forever under a single-shot runtime as well; panicking
/// says so at once instead of hanging the suite.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("this future was expected to complete on its first poll"),
    }
}
