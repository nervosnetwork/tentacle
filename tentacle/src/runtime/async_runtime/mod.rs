#[cfg(not(target_family = "wasm"))]
pub use async_std::task::{spawn, spawn_blocking, yield_now, JoinHandle};

pub fn block_in_place<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(not(target_family = "wasm"))]
pub use os::*;

#[cfg(not(target_family = "wasm"))]
mod os;
