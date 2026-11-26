import { useEffect, useRef, useState } from "react";

export type EventStreamStatus = "closed" | "connecting" | "open" | "error";

/**
 * Subscribe to `/api/v1/events/stream` (SSE).
 *
 * - The browser reconnects automatically and replays `Last-Event-ID`, so the
 *   server resumes after the last delivered row instead of duplicating it.
 * - `received` lets a view show "N new events" without re-rendering the table
 *   on every message; callers decide when to refetch.
 * - When the stream is disabled (paused tab, hidden document) the connection is
 *   closed and the page keeps its polling fallback.
 */
export function useEventStream(options: { enabled: boolean; onEvent?: (event: unknown) => void }) {
  const { enabled, onEvent } = options;
  const [status, setStatus] = useState<EventStreamStatus>("closed");
  const [received, setReceived] = useState(0);
  const handlerRef = useRef(onEvent);

  useEffect(() => {
    handlerRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (!enabled) {
      setStatus("closed");
      return;
    }
    if (typeof EventSource === "undefined") {
      setStatus("error");
      return;
    }
    const source = new EventSource("/api/v1/events/stream", { withCredentials: true });
    setStatus("connecting");
    source.addEventListener("open", () => setStatus("open"));
    source.addEventListener("security_event", (message) => {
      setReceived((value) => value + 1);
      try {
        handlerRef.current?.(JSON.parse((message as MessageEvent).data as string));
      } catch {
        /* a malformed frame must not tear down the stream */
      }
    });
    source.onerror = () => setStatus("error");
    return () => {
      source.close();
      setStatus("closed");
    };
  }, [enabled]);

  return { status, received, reset: () => setReceived(0) };
}
