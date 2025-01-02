use async_io::Timer;
use futures::{Future, Stream};
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub struct Delay(Timer);

impl Delay {
    pub fn new(duration: Duration) -> Self {
        Delay(Timer::after(duration))
    }
}

impl Future for Delay {
    type Output = Instant;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

pub fn delay_for(duration: Duration) -> Delay {
    Delay::new(duration)
}

pub struct Interval {
    delay: Delay,
    period: Duration,
}

impl Interval {
    fn new(period: Duration) -> Self {
        Self {
            delay: Delay::new(period),
            period,
        }
    }
}

impl Stream for Interval {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        match Pin::new(&mut self.delay).poll(cx) {
            Poll::Ready(_) => {
                let dur = self.period;
                self.delay.0.set_after(dur);
                Poll::Ready(Some(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub fn interval(period: Duration) -> Interval {
    assert!(period > Duration::new(0, 0), "`period` must be non-zero.");

    Interval::new(period)
}
