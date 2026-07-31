import { getAssetUrlsByImport } from "@tldraw/assets/imports.vite";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  handleNativeOrMenuCopy,
  serializeTldrawJson,
  Tldraw,
  type Editor,
} from "tldraw";
import { useDeepsecBridge } from "./api";
import {
  configurePresentationEditor,
  syncCanvasShapes,
} from "./canvasProjection";

const assetUrls = getAssetUrlsByImport();

export function App() {
  const { tokenPresent, canvasState, controlError } = useDeepsecBridge();
  const [editor, setEditor] = useState<Editor | null>(null);
  const latestState = useRef(canvasState);
  const projectionTimer = useRef<number | undefined>(undefined);
  const licenseKey = import.meta.env.VITE_TLDRAW_LICENSE_KEY || undefined;
  const transferMode = new URLSearchParams(window.location.search).get("transfer") === "1";

  latestState.current = canvasState;

  useEffect(() => {
    if (!editor || projectionTimer.current !== undefined) return;
    projectionTimer.current = window.setTimeout(() => {
      projectionTimer.current = undefined;
      syncCanvasShapes(editor, latestState.current);
    }, 34);
  }, [canvasState, editor]);

  useEffect(
    () => () => {
      if (projectionTimer.current !== undefined) {
        window.clearTimeout(projectionTimer.current);
      }
    },
    [],
  );

  const mountEditor = useMemo(
    () => (mountedEditor: Editor) => {
      setEditor(mountedEditor);
      syncCanvasShapes(mountedEditor, latestState.current);
      const teardownPresentation = configurePresentationEditor(mountedEditor);
      const host = window as Window & {
        __deepsecCopyBoard?: () => Promise<boolean>;
        __deepsecExportBoard?: () => Promise<string>;
      };
      host.__deepsecCopyBoard = async () => {
        mountedEditor.selectAll();
        const copied = await handleNativeOrMenuCopy(mountedEditor);
        mountedEditor.selectNone();
        return copied;
      };
      host.__deepsecExportBoard = () => serializeTldrawJson(mountedEditor);
      return () => {
        delete host.__deepsecCopyBoard;
        delete host.__deepsecExportBoard;
        teardownPresentation();
      };
    },
    [],
  );

  return (
    <main className="tldraw-shell">
      <Tldraw
        assetUrls={assetUrls}
        licenseKey={licenseKey}
        onMount={mountEditor}
        persistenceKey="deepsec-canvas-offline-v2"
      />
      {transferMode ? (
        <button
          className="transfer-button"
          disabled={!editor}
          onClick={() => {
            if (!editor) return;
            const shapes = editor.getCurrentPageShapes();
            const ids = shapes.map((shape) => shape.id);
            editor.run(
              () =>
                editor.updateShapes(
                  shapes.map((shape) => ({
                    id: shape.id,
                    type: shape.type,
                    isLocked: false,
                  })),
                ),
              { history: "ignore", ignoreShapeLock: true },
            );
            editor.setSelectedShapes(ids);
            void handleNativeOrMenuCopy(editor).finally(() => {
              editor.selectNone();
              editor.run(
                () =>
                  editor.updateShapes(
                    shapes.map((shape) => ({
                      id: shape.id,
                      type: shape.type,
                      isLocked: true,
                    })),
                  ),
                { history: "ignore", ignoreShapeLock: true },
              );
            });
          }}
          type="button"
        >
          COPY BOARD
        </button>
      ) : null}
      {!tokenPresent ? (
        <div className="alert danger-alert">
          Missing local bridge token. Reopen the launch URL.
        </div>
      ) : null}
      {controlError ? <div className="alert">{controlError}</div> : null}
    </main>
  );
}
