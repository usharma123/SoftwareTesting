import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  applyConnectionStatus,
  createInitialState,
  reduceCanvasEvent,
  type CanvasState,
  type StreamEnvelope,
} from "./state";

export type ConnectionStatus = "connecting" | "open" | "closed" | "error";

export interface BridgeStatus {
  bridge?: {
    state?: string;
    clients?: number;
    offline?: boolean;
  };
  run?: {
    sessionId?: string;
    mode?: "live" | "simulation";
    state?: string;
    targetRoot?: string;
    projectId?: string;
    eventCount?: number;
  };
  replay?: {
    active?: boolean;
    paused?: boolean;
    state?: string;
    index?: number;
    total?: number;
    position?: number;
    speed?: number;
  };
  [key: string]: unknown;
}

interface ApiResult {
  ok: boolean;
  status: number;
  body?: unknown;
}

function tokenFromBoot(): string {
  const query = new URLSearchParams(window.location.search).get("token");
  const meta = document
    .querySelector<HTMLMetaElement>('meta[name="deepsec-canvas-token"]')
    ?.content.trim();
  const prior = window.sessionStorage.getItem("deepsec-canvas-token");
  const token = query?.trim() || meta || prior || "";
  if (token) window.sessionStorage.setItem("deepsec-canvas-token", token);
  return token;
}

function withToken(path: string, token: string): string {
  const url = new URL(path, window.location.origin);
  if (token) url.searchParams.set("token", token);
  return `${url.pathname}${url.search}`;
}

async function parseResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) return response.json();
  const text = await response.text();
  return text || undefined;
}

export function useDeepsecBridge() {
  const token = useMemo(tokenFromBoot, []);
  const [canvasState, setCanvasState] = useState<CanvasState>(() => createInitialState());
  const [connection, setConnection] = useState<ConnectionStatus>("connecting");
  const [bridgeStatus, setBridgeStatus] = useState<BridgeStatus>({});
  const [streamSource, setStreamSource] = useState<StreamEnvelope["source"]>("bridge");
  const [lastSeq, setLastSeq] = useState(0);
  const [controlError, setControlError] = useState<string>();
  const sourceRef = useRef<EventSource | undefined>(undefined);

  const refreshStatus = useCallback(async () => {
    try {
      const response = await fetch(withToken("/api/status", token), {
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`Status request failed (${response.status})`);
      setBridgeStatus((await response.json()) as BridgeStatus);
    } catch (error) {
      setControlError(error instanceof Error ? error.message : "Status request failed");
    }
  }, [token]);

  const post = useCallback(
    async (path: string, body?: unknown): Promise<ApiResult> => {
      setControlError(undefined);
      try {
        const response = await fetch(path, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-DeepSec-Canvas-Token": token,
          },
          body: JSON.stringify(body ?? {}),
        });
        const result = {
          ok: response.ok,
          status: response.status,
          body: await parseResponse(response),
        };
        if (!response.ok) {
          const message =
            result.body &&
            typeof result.body === "object" &&
            "error" in result.body &&
            typeof result.body.error === "string"
              ? result.body.error
              : `Control request failed (${response.status})`;
          throw new Error(message);
        }
        await refreshStatus();
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : "Control request failed";
        setControlError(message);
        return { ok: false, status: 0, body: { error: message } };
      }
    },
    [refreshStatus, token],
  );

  useEffect(() => {
    setConnection("connecting");
    const source = new EventSource(withToken("/api/events", token));
    sourceRef.current = source;

    const consume = (message: MessageEvent<string>) => {
      try {
        const parsed = JSON.parse(message.data) as StreamEnvelope | Record<string, unknown>;
        const envelope =
          parsed &&
          typeof parsed === "object" &&
          "event" in parsed &&
          parsed.event !== null &&
          typeof parsed.event === "object"
            ? (parsed as StreamEnvelope)
            : ({ source: "bridge", event: parsed } as StreamEnvelope);
        const kind =
          envelope.event &&
          typeof envelope.event === "object" &&
          typeof envelope.event.kind === "string"
            ? envelope.event.kind
            : undefined;
        setCanvasState((current) =>
          kind === "canvas-reset" || kind === "replay-reset"
            ? createInitialState("running")
            : reduceCanvasEvent(current, envelope),
        );
        if (typeof envelope.seq === "number") setLastSeq(envelope.seq);
        if (envelope.source) setStreamSource(envelope.source);
      } catch {
        setCanvasState((current) => ({ ...current, malformedEvents: current.malformedEvents + 1 }));
      }
    };

    source.addEventListener("canvas-event", consume as EventListener);
    source.onmessage = consume;
    source.onopen = () => {
      setConnection("open");
      setCanvasState((current) => applyConnectionStatus(current, "open"));
      setControlError(undefined);
    };
    source.onerror = () => {
      const next = source.readyState === EventSource.CLOSED ? "closed" : "error";
      setConnection(next);
      setCanvasState((current) => applyConnectionStatus(current, next));
    };

    return () => {
      source.removeEventListener("canvas-event", consume as EventListener);
      source.close();
      sourceRef.current = undefined;
      setConnection("closed");
    };
  }, [token]);

  useEffect(() => {
    void refreshStatus();
    const timer = window.setInterval(() => void refreshStatus(), 5_000);
    return () => window.clearInterval(timer);
  }, [refreshStatus]);

  const controls = useMemo(
    () => ({
      startSimulation: () =>
        post("/api/start", {
          mode: "simulation",
          options: { limit: 18, concurrency: 2, maxTurns: 40 },
        }),
      startLive: () =>
        bridgeStatus.run?.targetRoot
          ? post("/api/start", {
              mode: "live",
              options: {
                root: bridgeStatus.run.targetRoot,
                projectId: bridgeStatus.run.projectId,
                limit: 18,
                concurrency: 2,
                maxTurns: 40,
                skipSetup: true,
              },
            })
          : Promise.resolve({
              ok: false,
              status: 0,
              body: { error: "Start the first live run with the documented CLI target options." },
            }),
      stop: () => post("/api/stop"),
      replayStart: (sessionId?: string, speed = 1) =>
        post("/api/replay/start", { sessionId, speed }),
      replayPause: () => post("/api/replay/pause"),
      replayResume: () => post("/api/replay/resume"),
      replaySeek: (position: number) => post("/api/replay/seek", { position }),
      replayStop: () => post("/api/replay/stop"),
    }),
    [bridgeStatus.run?.projectId, bridgeStatus.run?.targetRoot, post],
  );

  return {
    tokenPresent: Boolean(token),
    canvasState,
    connection,
    bridgeStatus,
    streamSource,
    lastSeq,
    controlError,
    controls,
  };
}
