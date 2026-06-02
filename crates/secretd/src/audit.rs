//! Event drain/forward: bridges the engine's SYNC `std::sync::mpsc` `SecretEvent` stream into the
//! async tonic server-stream of proto `Event`s.
//!
//! The engine commits every security OUTCOME to its durable, hash-chained audit log BEFORE the RPC
//! method returns (HF-14); this channel is the cosmetic/best-effort mirror. Because the engine emits
//! synchronously DURING the call, by the time the sync engine method returns ALL of its events are
//! already queued on the std `Receiver`. We therefore run the engine call on a `spawn_blocking` task
//! that OWNS the std `rx`, drop the `EventSink` when the call returns (closing the channel), then
//! drain `rx` into a `tokio::sync::mpsc` whose receiver becomes the response stream.
use envctl_secrets::{Engine, EventSink};
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use crate::conv;

/// The response-stream type every streaming RPC returns.
pub type EventStream = ReceiverStream<Result<envctl_secrets_proto::v1::Event, Status>>;

/// Run a SYNC engine call that emits events, bridging its `SecretEvent`s onto a tonic server-stream.
///
/// `f` is the engine call; it receives the per-RPC `EventSink` and returns the engine's
/// `anyhow::Result<()>`. The call runs on `spawn_blocking` (REQUIRED: the libSQL-backed store does
/// real blocking syscalls and would stall the reactor; for InMemStore it is cheap-but-correct). The
/// `SecretEvent`s are converted via `conv::event_to_proto` (variants with no proto twin are filtered
/// out). A setup-time `Err` from the engine is surfaced as a terminal `Err(Status)` item on the
/// stream so the client observes the failure.
pub fn run_streaming<F>(engine: Engine, f: F) -> EventStream
where
    F: FnOnce(&Engine, &EventSink) -> anyhow::Result<()> + Send + 'static,
{
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<_, Status>>(64);
    tokio::task::spawn_blocking(move || {
        let (sink, rx) = EventSink::channel();
        // Run the engine call; it emits all of its events synchronously before returning.
        let result = f(&engine, &sink);
        // Drop the sink so the std `Receiver` terminates once drained.
        drop(sink);
        // Drain every queued event, forwarding the ones that have a proto twin.
        while let Ok(ev) = rx.recv() {
            if let Some(proto) = conv::event_to_proto(ev) {
                if out_tx.blocking_send(Ok(proto)).is_err() {
                    return; // client hung up
                }
            }
        }
        // A setup-time engine error becomes a terminal stream error.
        if let Err(e) = result {
            let _ = out_tx.blocking_send(Err(Status::internal(e.to_string())));
        }
    });
    ReceiverStream::new(out_rx)
}
