import type { ExploreStreamEvent } from "./types.js";

/**
 * Structured events share stdout with the normal human-readable CLI log. The
 * prefix lets desktop clients identify event records without scraping prose,
 * while preserving the existing terminal and CI experience when streaming is
 * disabled.
 */
export const EXPLORE_EVENT_PREFIX = "@@deepsec:event@@";

export function createProcessExploreEventSink(
  env: NodeJS.ProcessEnv = process.env,
  write: (chunk: string) => void = (chunk) => process.stdout.write(chunk),
): ((event: ExploreStreamEvent) => void) | undefined {
  if (env.DEEPSEC_EVENT_STREAM !== "1") return undefined;

  return (event) => {
    write(`${EXPLORE_EVENT_PREFIX}${JSON.stringify(event)}\n`);
  };
}
