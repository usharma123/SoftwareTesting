import {
  Box,
  createShapeId,
  toRichText,
  type Editor,
  type TLDefaultColorStyle,
  type TLGeoShape,
  type TLShapePartial,
} from "tldraw";
import type {
  AttemptState,
  AttemptStatus,
  CanvasState,
  FindingState,
  PhaseStatus,
} from "./state";

export const WORLD_BOUNDS = new Box(0, 0, 1600, 900);

type GeoShape = TLShapePartial<TLGeoShape>;

const ATTEMPT_X = [40, 428, 816] as const;
const ATTEMPT_Y = 214;
const ATTEMPT_W = 370;
const ATTEMPT_H = 96;
const ATTEMPT_GAP_Y = 13;
const FINDING_X = 1222;
const FINDING_Y = 250;
const FINDING_W = 330;
const FINDING_H = 88;
const FINDING_GAP_Y = 12;
const MAX_FINDING_SHAPES = 6;

function shapeId(value: string) {
  return createShapeId(`deepsec-${value}`);
}

function geo(
  id: string,
  x: number,
  y: number,
  w: number,
  h: number,
  text: string,
  color: TLDefaultColorStyle,
  options: {
    fill?: "none" | "semi" | "solid" | "pattern" | "fill";
    dash?: "draw" | "solid" | "dashed" | "dotted";
    size?: "s" | "m" | "l" | "xl";
    opacity?: number;
    align?: "start" | "middle" | "end";
    verticalAlign?: "start" | "middle" | "end";
    labelColor?: TLDefaultColorStyle;
  } = {},
): GeoShape {
  return {
    id: shapeId(id),
    type: "geo",
    x,
    y,
    isLocked: true,
    opacity: options.opacity ?? 1,
    props: {
      geo: "rectangle",
      w,
      h,
      growY: 0,
      scale: 1,
      url: "",
      dash: options.dash ?? "solid",
      color,
      labelColor: options.labelColor ?? color,
      fill: options.fill ?? "solid",
      size: options.size ?? "s",
      font: "sans",
      align: options.align ?? "start",
      verticalAlign: options.verticalAlign ?? "start",
      richText: toRichText(text),
    },
  };
}

function phaseColor(status: PhaseStatus): TLDefaultColorStyle {
  switch (status) {
    case "active":
      return "blue";
    case "complete":
      return "green";
    case "skipped":
      return "yellow";
    case "failed":
      return "red";
    default:
      return "grey";
  }
}

function attemptColor(status: AttemptStatus): TLDefaultColorStyle {
  switch (status) {
    case "exploring":
      return "blue";
    case "validating":
      return "violet";
    case "complete":
      return "green";
    case "failed":
      return "red";
    case "queued":
      return "yellow";
    default:
      return "grey";
  }
}

function findingColor(finding: FindingState): TLDefaultColorStyle {
  if (finding.status === "rejected") return "grey";
  if (finding.status === "uncertain") return "yellow";
  if (finding.status === "candidate") return "orange";
  switch (finding.severity?.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return "red";
    case "MEDIUM":
      return "orange";
    case "LOW":
      return "yellow";
    default:
      return "green";
  }
}

function compactTokens(value: number): string {
  if (value < 1_000) return String(value);
  if (value < 1_000_000) return `${(value / 1_000).toFixed(value < 10_000 ? 1 : 0)}K`;
  return `${(value / 1_000_000).toFixed(1)}M`;
}

function basename(path?: string): string {
  if (!path) return "Awaiting ranked file";
  return path.split(/[\\/]/).at(-1) || path;
}

function compact(value: string, maxLength: number): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length <= maxLength
    ? singleLine
    : `${singleLine.slice(0, maxLength - 1)}…`;
}

function attemptLabel(attempt: AttemptState): string {
  const worker = attempt.workerSlot ? ` · WORKER ${attempt.workerSlot}` : "";
  const phase =
    attempt.status === "validating"
      ? "VALIDATE"
      : attempt.status === "exploring"
        ? "EXPLORE"
        : attempt.status.toUpperCase();
  const tokens = attempt.usage.inputTokens + attempt.usage.outputTokens;
  const progress =
    attempt.maxTurns > 0
      ? `TURN ${attempt.turn}/${attempt.maxTurns} · ${compactTokens(tokens)} TOK`
      : `${compactTokens(tokens)} TOKENS`;
  return [
    `${String(attempt.index + 1).padStart(2, "0")}${worker} · ${phase}`,
    compact(basename(attempt.focusFile), 36),
    progress,
    compact(attempt.lastAction, 49),
  ].join("\n");
}

function attemptShapes(attempt: AttemptState): GeoShape[] {
  const column = attempt.index % 3;
  const row = Math.floor(attempt.index / 3);
  const x = ATTEMPT_X[column];
  const y = ATTEMPT_Y + row * (ATTEMPT_H + ATTEMPT_GAP_Y);
  const color = attemptColor(attempt.status);
  const active = attempt.status === "exploring" || attempt.status === "validating";
  const progress =
    attempt.maxTurns > 0 ? Math.min(1, Math.max(0, attempt.turn / attempt.maxTurns)) : 0;

  return [
    geo(
      `attempt-${attempt.index}-card`,
      x,
      y,
      ATTEMPT_W,
      ATTEMPT_H,
      attemptLabel(attempt),
      color,
      {
        fill: attempt.status === "awaiting" ? "semi" : "solid",
        opacity: attempt.status === "awaiting" ? 0.52 : 0.92,
      },
    ),
    geo(
      `attempt-${attempt.index}-active-accent`,
      x - 4,
      y - 4,
      ATTEMPT_W + 8,
      ATTEMPT_H + 8,
      "",
      attempt.status === "validating" ? "violet" : "blue",
      {
        fill: "none",
        dash: active ? "solid" : "dotted",
        size: "m",
        opacity: active ? 1 : 0.02,
      },
    ),
    geo(
      `attempt-${attempt.index}-progress-track`,
      x + 14,
      y + ATTEMPT_H - 11,
      ATTEMPT_W - 28,
      4,
      "",
      "grey",
      { fill: "solid", opacity: 0.34 },
    ),
    geo(
      `attempt-${attempt.index}-progress-value`,
      x + 14,
      y + ATTEMPT_H - 11,
      Math.max(progress > 0 ? 4 : 0.5, (ATTEMPT_W - 28) * progress),
      4,
      "",
      active ? color : attempt.status === "complete" ? "green" : "grey",
      { fill: "solid", opacity: progress > 0 ? 1 : 0.02 },
    ),
  ];
}

function findingLabel(finding: FindingState): string {
  const severity = finding.severity?.toUpperCase() ?? "PENDING";
  const status =
    finding.status === "accepted"
      ? "VALIDATED"
      : finding.status === "rejected"
        ? "REJECTED"
        : finding.status.toUpperCase();
  const location =
    finding.lineNumbers && finding.lineNumbers.length > 0
      ? ` · L${finding.lineNumbers.slice(0, 3).join(",")}`
      : "";
  return [
    `${severity} · ${status}`,
    compact(finding.title, 37),
    `ATTEMPT ${String(finding.attemptIndex + 1).padStart(2, "0")}${location}`,
    compact(finding.vulnSlug ?? finding.confidence ?? "Awaiting artifact hydration", 42),
  ].join("\n");
}

function findingShapes(findings: FindingState[]): GeoShape[] {
  const shapes: GeoShape[] = [];
  const visible = findings.slice(0, MAX_FINDING_SHAPES);
  for (const [slot, finding] of visible.entries()) {
    shapes.push(
      geo(
        `finding-${finding.id}`,
        FINDING_X,
        FINDING_Y + slot * (FINDING_H + FINDING_GAP_Y),
        FINDING_W,
        FINDING_H,
        findingLabel(finding),
        findingColor(finding),
        {
          fill: finding.status === "rejected" ? "semi" : "solid",
          opacity: finding.status === "rejected" ? 0.55 : 0.96,
        },
      ),
    );
  }

  if (findings.length > MAX_FINDING_SHAPES) {
    shapes.push(
      geo(
        "finding-overflow",
        FINDING_X + 190,
        822,
        140,
        36,
        `+${findings.length - MAX_FINDING_SHAPES} MORE`,
        "orange",
        { align: "middle", verticalAlign: "middle", fill: "semi" },
      ),
    );
  }
  return shapes;
}

export function projectStateToShapes(state: CanvasState): GeoShape[] {
  const completed = state.attempts.filter((attempt) => attempt.status === "complete").length;
  const active = state.attempts.filter(
    (attempt) => attempt.status === "exploring" || attempt.status === "validating",
  ).length;
  const accepted = state.findings.filter((finding) => finding.status === "accepted").length;
  const totalTokens = state.usage.inputTokens + state.usage.outputTokens;
  const statusColor: TLDefaultColorStyle =
    state.status === "complete"
      ? "green"
      : state.status === "failed"
        ? "red"
        : state.status === "running"
          ? "blue"
          : "grey";
  const shapes: GeoShape[] = [
    geo("world-background", 0, 0, 1600, 900, "", "black", {
      fill: "solid",
      opacity: 1,
    }),
    geo(
      "run-title",
      30,
      20,
      500,
      66,
      `DEEPSEC · LIVE GVISOR RUN\n${state.projectId ?? "WAITING FOR RUN"} · ${state.runId ?? "OFFLINE TLDRAW"}`,
      "blue",
      { fill: "solid", size: "m", verticalAlign: "middle" },
    ),
    geo("run-status", 548, 20, 210, 66, `STATUS\n${state.status.toUpperCase()}`, statusColor, {
      fill: "solid",
      verticalAlign: "middle",
    }),
    geo(
      "run-attempts",
      776,
      20,
      210,
      66,
      `ATTEMPTS\n${completed}/18 · ${active}/2 ACTIVE`,
      active > 0 ? "blue" : completed === 18 ? "green" : "grey",
      { fill: "solid", verticalAlign: "middle" },
    ),
    geo(
      "run-tokens",
      1004,
      20,
      210,
      66,
      `TOKENS\n${compactTokens(totalTokens)}`,
      "violet",
      { fill: "solid", verticalAlign: "middle" },
    ),
    geo(
      "run-findings",
      1232,
      20,
      338,
      66,
      `FINDINGS\n${accepted} VALIDATED · ${state.findings.length} SEEN`,
      accepted > 0 ? "orange" : "grey",
      { fill: "solid", verticalAlign: "middle" },
    ),
    geo("phase-rail-frame", 30, 104, 1540, 82, "", "grey", {
      fill: "semi",
      dash: "solid",
      opacity: 0.62,
    }),
    geo("attempt-grid-frame", 26, 198, 1174, 666, "", "grey", {
      fill: "semi",
      dash: "solid",
      opacity: 0.38,
    }),
    geo(
      "finding-rail-frame",
      1208,
      198,
      362,
      666,
      "FINDINGS / LIVE EVIDENCE",
      "grey",
      {
        fill: "semi",
        dash: "solid",
        opacity: 0.54,
        verticalAlign: "start",
      },
    ),
  ];

  state.phases.forEach((phase, index) => {
    const x = 42 + index * 169;
    const color = phaseColor(phase.status);
    shapes.push(
      geo(
        `phase-${phase.id}`,
        x,
        115,
        150,
        58,
        `${String(index + 1).padStart(2, "0")} · ${phase.label.toUpperCase()}\n${phase.status.toUpperCase()}`,
        color,
        {
          fill: phase.status === "pending" ? "semi" : "solid",
          opacity: phase.status === "pending" ? 0.48 : 0.96,
          verticalAlign: "middle",
        },
      ),
    );
    if (index < state.phases.length - 1) {
      shapes.push(
        geo(
          `phase-connector-${index}`,
          x + 150,
          142,
          19,
          4,
          "",
          phase.status === "complete" || phase.status === "skipped" ? "green" : "grey",
          {
            fill: "solid",
            opacity: phase.status === "complete" || phase.status === "skipped" ? 0.9 : 0.25,
          },
        ),
      );
    }
  });

  for (const attempt of state.attempts) shapes.push(...attemptShapes(attempt));
  shapes.push(...findingShapes(state.findings));
  return shapes;
}

export function syncCanvasShapes(editor: Editor, state: CanvasState): void {
  const shapes = projectStateToShapes(state);
  const desiredIds = new Set(shapes.map((shape) => shape.id));
  const creates: GeoShape[] = [];
  const updates: GeoShape[] = [];
  const deletes = [...editor.getCurrentPageShapeIds()].filter(
    (id) => String(id).startsWith("shape:deepsec-") && !desiredIds.has(id),
  );
  for (const shape of shapes) {
    if (editor.getShape(shape.id)) updates.push(shape);
    else creates.push(shape);
  }

  editor.run(
    () => {
      if (deletes.length > 0) editor.deleteShapes(deletes);
      if (creates.length > 0) editor.createShapes(creates);
      if (updates.length > 0) editor.updateShapes(updates);
    },
    { history: "ignore", ignoreShapeLock: true },
  );
}

export function fitMissionControl(editor: Editor, animated = true): void {
  editor.zoomToBounds(WORLD_BOUNDS, {
    inset: 0,
    animation: animated ? { duration: 240 } : undefined,
    immediate: !animated,
  });
}

export function configurePresentationEditor(editor: Editor): () => void {
  editor.user.updateUserPreferences({ colorScheme: "dark" });
  editor.setCurrentTool("hand");
  fitMissionControl(editor, false);
  return () => {};
}
