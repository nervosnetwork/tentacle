//! Bounded inbound handshake scheduling, shared by the service listen paths.

use std::{future::Future, sync::Arc, time::Duration};

use futures::{Stream, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::sync::Semaphore;

use super::error::QuicErrorKind;

/// Own every handshake and result-delivery future in the listener task. Dropping
/// this future cancels pending work and returns its permits without closing
/// connections already delivered to the service.
pub(crate) async fn drive<I, T, S, H, F, D, G, R>(
    incoming: S,
    permits: Arc<Semaphore>,
    deadline: Duration,
    mut handshake: H,
    deliver: D,
    mut reject: R,
) where
    S: Stream<Item = I>,
    T: Send + 'static,
    H: FnMut(I) -> F,
    F: Future<Output = Result<T, QuicErrorKind>> + Send + 'static,
    D: Fn(Result<T, QuicErrorKind>) -> G + Clone + Send + 'static,
    G: Future<Output = bool> + Send + 'static,
    R: FnMut(I),
{
    futures::pin_mut!(incoming);
    let mut pending = FuturesUnordered::<BoxFuture<'static, bool>>::new();
    loop {
        tokio::select! {
            completed = pending.next(), if !pending.is_empty() => {
                // A closed result receiver means the service has shut down.
                if completed == Some(false) {
                    return;
                }
            }
            next = incoming.next() => {
                let Some(incoming) = next else { return };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    reject(incoming);
                    continue;
                };
                // Start the absolute deadline at admission, not at first poll.
                let handshake = crate::runtime::timeout(deadline, handshake(incoming));
                let deliver = deliver.clone();
                pending.push(Box::pin(async move {
                    let result = handshake.await
                        .unwrap_or(Err(QuicErrorKind::HandshakeTimedOut(deadline)));
                    // Delivery is part of the bounded job. A slow consumer must
                    // not create an unbounded queue of completed connections or
                    // prevent other jobs' handshake timers from being polled.
                    let keep_running = deliver(result).await;
                    drop(permit);
                    keep_running
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{
        FutureExt,
        channel::{mpsc, oneshot},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Outcome = Result<usize, QuicErrorKind>;
    type Input = oneshot::Receiver<Outcome>;

    struct Harness {
        input: mpsc::UnboundedSender<Input>,
        results: mpsc::UnboundedReceiver<Outcome>,
        rejected: Arc<AtomicUsize>,
        driver: BoxFuture<'static, ()>,
    }

    impl Harness {
        fn new(
            permits: Arc<Semaphore>,
            timeout: Duration,
            block_delivery: bool,
            receiver_open: bool,
        ) -> Self {
            let (input, incoming) = mpsc::unbounded();
            let (output, results) = mpsc::unbounded();
            let rejected = Arc::new(AtomicUsize::new(0));
            let reject_count = rejected.clone();
            let driver = drive(
                incoming,
                permits,
                timeout,
                |input: Input| async move { input.await.expect("test handshake sender dropped") },
                move |result| {
                    output.unbounded_send(result).unwrap();
                    async move {
                        if block_delivery {
                            futures::future::pending::<()>().await;
                        }
                        receiver_open
                    }
                },
                move |_| {
                    reject_count.fetch_add(1, Ordering::SeqCst);
                },
            )
            .boxed();
            Self {
                input,
                results,
                rejected,
                driver,
            }
        }

        fn admit(&mut self) -> oneshot::Sender<Outcome> {
            let (tx, rx) = oneshot::channel();
            self.input.unbounded_send(rx).unwrap();
            let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
            assert!(self.driver.as_mut().poll(&mut cx).is_pending());
            tx
        }

        async fn next_result(&mut self) -> Outcome {
            crate::runtime::timeout(Duration::from_secs(2), async {
                tokio::select! {
                    _ = &mut self.driver => panic!("driver unexpectedly stopped"),
                    result = self.results.next() => result.unwrap(),
                }
            })
            .await
            .expect("driver did not make progress")
        }
    }

    #[tokio::test]
    async fn stalled_handshake_does_not_block_success_or_failure() {
        let permits = Arc::new(Semaphore::new(3));
        let mut harness = Harness::new(permits.clone(), Duration::from_secs(30), false, true);
        let _stalled = harness.admit();
        let ready = harness.admit();
        ready.send(Ok(7)).unwrap();
        assert_eq!(harness.next_result().await.unwrap(), 7);
        assert_eq!(permits.available_permits(), 2);
        let failed = harness.admit();
        failed
            .send(Err(QuicErrorKind::TlsConfig("test failure".into())))
            .unwrap();
        assert!(matches!(
            harness.next_result().await,
            Err(QuicErrorKind::TlsConfig(_))
        ));
        assert_eq!(permits.available_permits(), 2);
        drop(harness);
        assert_eq!(permits.available_permits(), 3);
    }

    #[tokio::test]
    async fn listeners_share_capacity_and_cancellation_returns_it() {
        let permits = Arc::new(Semaphore::new(1));
        let mut first = Harness::new(permits.clone(), Duration::from_secs(30), false, true);
        let mut second = Harness::new(permits.clone(), Duration::from_secs(30), false, true);
        let stalled = first.admit();
        assert_eq!(permits.available_permits(), 0);
        let rejected = second.admit();
        assert!(rejected.is_canceled());
        assert_eq!(second.rejected.load(Ordering::SeqCst), 1);
        drop(first);
        assert!(stalled.is_canceled());
        assert_eq!(permits.available_permits(), 1);
        second.admit().send(Ok(9)).unwrap();
        assert_eq!(second.next_result().await.unwrap(), 9);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn backpressure_keeps_permits_but_does_not_block_other_deadlines() {
        let permits = Arc::new(Semaphore::new(2));
        let mut harness = Harness::new(permits.clone(), Duration::from_millis(50), true, true);
        harness.admit().send(Ok(1)).unwrap();
        assert_eq!(harness.next_result().await.unwrap(), 1);
        let stalled = harness.admit();
        assert_eq!(permits.available_permits(), 0);
        assert!(matches!(
            harness.next_result().await,
            Err(QuicErrorKind::HandshakeTimedOut(_))
        ));
        assert!(stalled.is_canceled());
        assert_eq!(permits.available_permits(), 0);
        assert!(harness.admit().is_canceled());
        drop(harness);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn timeout_returns_capacity_when_delivery_completes() {
        let permits = Arc::new(Semaphore::new(1));
        let mut harness = Harness::new(permits.clone(), Duration::from_millis(20), false, true);
        let stalled = harness.admit();
        assert!(matches!(
            harness.next_result().await,
            Err(QuicErrorKind::HandshakeTimedOut(_))
        ));
        assert!(stalled.is_canceled());
        assert_eq!(permits.available_permits(), 1);
        harness.admit().send(Ok(2)).unwrap();
        assert_eq!(harness.next_result().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn receiver_shutdown_cancels_remaining_work() {
        let permits = Arc::new(Semaphore::new(2));
        let mut harness = Harness::new(permits.clone(), Duration::from_secs(30), false, false);
        let stalled = harness.admit();
        harness.admit().send(Ok(1)).unwrap();
        crate::runtime::timeout(Duration::from_secs(2), harness.driver)
            .await
            .unwrap();
        assert!(stalled.is_canceled());
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn endpoint_shutdown_cancels_remaining_work() {
        let permits = Arc::new(Semaphore::new(1));
        let mut harness = Harness::new(permits.clone(), Duration::from_secs(30), false, true);
        let stalled = harness.admit();
        harness.input.close_channel();
        crate::runtime::timeout(Duration::from_secs(2), harness.driver)
            .await
            .unwrap();
        assert!(stalled.is_canceled());
        assert_eq!(permits.available_permits(), 1);
    }
}
