// src/content/FloatingWidget.tsx
import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
} from "react";
import { Sprite } from "./Sprite";
import { IdeaSprite } from "./IdeaSprite";
import { PanelFrame } from "./PanelFrame";
import { MenuButton } from "./MenuButton";
import { useTabActive } from "./hooks/useTabActive";

type CommentStatus = "idle" | "pending" | "done" | "error";
type RecapStatus = "idle" | "loading" | "ready" | "error";

interface WidgetConfig {
  pageId?: string;
  apiBase?: string;
  staticBase?: string;
}

interface FloatingWidgetProps {
  config: WidgetConfig;
}

interface Pos {
  left: number;
  bottom: number;
}

const SPRITE_SIZE = 64;
const IDEA_SIZE = 32;
const RECAP_ICON_SIZE = 32;

// Clamp avatar position so it doesn't go off-screen
function clampPosToViewport(
  pos: Pos,
  viewportWidth: number,
  viewportHeight: number
): Pos {
  const margin = 8;
  const maxLeft = Math.max(margin, viewportWidth - SPRITE_SIZE - margin);
  const maxBottom = Math.max(margin, viewportHeight - SPRITE_SIZE - margin);

  return {
    left: Math.min(Math.max(pos.left, margin), maxLeft),
    bottom: Math.min(Math.max(pos.bottom, margin), maxBottom),
  };
}

// Decide where to place the recap panel
function computePanelPosition(
  pos: Pos,
  viewportWidth: number,
  viewportHeight: number,
  panelWidth = 380,
  panelHeight = 480
): Pos {
  const spriteCenterX = pos.left + SPRITE_SIZE / 2;
  let left = spriteCenterX - panelWidth / 2;

  const margin = 8;
  left = Math.max(margin, Math.min(left, viewportWidth - panelWidth - margin));

  const spaceAbove = viewportHeight - (pos.bottom + SPRITE_SIZE);
  const spaceBelow = pos.bottom;

  const openAbove =
    spaceAbove > panelHeight || spaceAbove > spaceBelow;

  let bottom: number;
  if (openAbove) {
    // panel above sprite
    bottom = pos.bottom + SPRITE_SIZE + 8;
  } else {
    // panel below sprite
    bottom = pos.bottom - panelHeight - 8;
    bottom = Math.max(margin, bottom);
  }

  return { left, bottom };
}

export const FloatingWidget: React.FC<FloatingWidgetProps> = ({ config }) => {
  const apiBase = config.apiBase?.replace(/\/$/, "") || "";
  const staticBase = (config.staticBase || "").replace(/\/$/, "");
  const isTabActive = useTabActive();

  // Avatar position (null = not yet loaded → don't render)
  const [pos, setPos] = useState<Pos | null>(null);

  const [viewportWidth, setViewportWidth] = useState<number>(
    typeof window !== "undefined" ? window.innerWidth : 0
  );
  const [viewportHeight, setViewportHeight] = useState<number>(
    typeof window !== "undefined" ? window.innerHeight : 0
  );

  // Drag flag (so click after drag doesn’t toggle menu)
  const [isDragging, setIsDragging] = useState(false);

  // Small menu next to sprite
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  // Recap panel
  const [isRecapOpen, setIsRecapOpen] = useState(false);
  const [recapStatus, setRecapStatus] = useState<RecapStatus>("idle");
  const [recapText, setRecapText] = useState<string | null>(null);
  const [recapUpdatedAt, setRecapUpdatedAt] = useState<number | null>(null);

  // Comment (lightbulb)
  const [comment, setComment] = useState<string | null>(null);
  const [commentStatus, setCommentStatus] =
    useState<CommentStatus>("idle");
  const [commentViewed, setCommentViewed] = useState(false);

  // ---------- SESSION STATE ----------
  // Global logical session: only two states: running or not
  const [sessionActive, setSessionActive] = useState<boolean>(false);

  // Track viewport size (for clamping + panel placement)
  useEffect(() => {
    function onResize() {
      setViewportWidth(window.innerWidth);
      setViewportHeight(window.innerHeight);
    }
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // --------- GLOBAL POSITION + SESSION SYNC ON TAB ACTIVE ---------
  useEffect(() => {
    if (!apiBase) return;
    if (!isTabActive) return;

    let cancelled = false;

    (async () => {
      try {
        const res = await fetch(`${apiBase}/widget-state`);
        if (!res.ok) throw new Error("state fetch failed");
        const data = await res.json();

        const serverPos: Pos = {
          left: typeof data.left === "number" ? data.left : 120,
          bottom: typeof data.bottom === "number" ? data.bottom : 80,
        };
        const clamped = clampPosToViewport(
          serverPos,
          viewportWidth,
          viewportHeight
        );

        if (!cancelled) {
          setPos(clamped);
          if (typeof data.session_running === "boolean") {
            setSessionActive(data.session_running);
          }
        }
      } catch {
        const fallback = clampPosToViewport(
          { left: 120, bottom: 80 },
          viewportWidth,
          viewportHeight
        );
        if (!cancelled) {
          setPos(fallback);
          // leave sessionActive as-is on error
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [apiBase, isTabActive, viewportWidth, viewportHeight]);

  // ---------- ACTIVE TIME TRACKING ----------
  // When tab is active, this holds the timestamp (sec) when it became active
  const lastActiveStartRef = useRef<number | null>(null);

  const sendPageActive = useCallback(
    async (deltaSeconds: number) => {
      // Only track when a session is actually running
      if (!apiBase) return;
      if (!config.pageId) return;
      if (deltaSeconds <= 0) return;
      if (!sessionActive) return;

      try {
        await fetch(`${apiBase}/page-active`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            page_id: config.pageId,
            delta_seconds: deltaSeconds,
          }),
        });
      } catch {
        // best-effort; ignore errors
      }
    },
    [apiBase, config.pageId, sessionActive]
  );

  // React to tab becoming active/inactive
  useEffect(() => {
    const now = Date.now() / 1000;

    if (isTabActive) {
      // Always reset local timer when tab becomes active
      lastActiveStartRef.current = now;
    } else {
      const start = lastActiveStartRef.current;
      if (start != null && sessionActive) {
        const delta = now - start;
        lastActiveStartRef.current = null;
        void sendPageActive(delta);
      }
    }
  }, [isTabActive, sendPageActive, sessionActive]);

  // Flush on unload / pagehide so we don't lose the last bit of time
  // (only if a session is active)
  useEffect(() => {
    if (!apiBase || !config.pageId) return;

    const handleUnloadLike = () => {
      if (!sessionActive) return;

      const start = lastActiveStartRef.current;
      if (start == null) return;

      const now = Date.now() / 1000;
      const delta = now - start;
      lastActiveStartRef.current = null;

      const payload = JSON.stringify({
        page_id: config.pageId,
        delta_seconds: delta,
      });

      if (navigator.sendBeacon) {
        navigator.sendBeacon(`${apiBase}/page-active`, payload);
      } else {
        void fetch(`${apiBase}/page-active`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: payload,
          keepalive: true as any,
        });
      }
    };

    window.addEventListener("beforeunload", handleUnloadLike);
    window.addEventListener("pagehide", handleUnloadLike);

    return () => {
      window.removeEventListener("beforeunload", handleUnloadLike);
      window.removeEventListener("pagehide", handleUnloadLike);
    };
  }, [apiBase, config.pageId, sessionActive]);

  // Helper: flush current active time *right now* (used before recap)
  const flushActiveTimeNow = useCallback(async () => {
    if (!sessionActive) return;

    const start = lastActiveStartRef.current;
    if (start == null) return;

    const now = Date.now() / 1000;
    const delta = now - start;
    lastActiveStartRef.current = now;

    await sendPageActive(delta);
  }, [sendPageActive, sessionActive]);

  // ---------- COMMENT (LIGHTBULB) ----------

  const fetchComment = useCallback(
    async (force: boolean) => {
      if (!config.pageId || !apiBase) return;

      setCommentStatus("pending");

      const params = new URLSearchParams();
      params.set("id", config.pageId);
      if (force) params.set("force", "true");

      try {
        const res = await fetch(
          `${apiBase}/page-comment?${params.toString()}`,
          { cache: "no-store" }
        );
        const data = await res.json();

        if (data.status === "done" && typeof data.comment === "string") {
          setComment(data.comment);
          setCommentStatus("done");
          // make bulb visible again even if user dismissed it before
          setCommentViewed(false);
        } else {
          setCommentStatus("error");
        }
      } catch {
        setCommentStatus("error");
      }
    },
    [config.pageId, apiBase]
  );

  // Initial load: get comment once for this page
  useEffect(() => {
    void fetchComment(false);
  }, [fetchComment]);

  // ---------- POSITION PERSISTENCE ----------

  const persistPos = useCallback(
    async (newPos: Pos) => {
      if (!apiBase) return;
      try {
        await fetch(`${apiBase}/widget-pos`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(newPos),
        });
      } catch {
        // ignore network errors here
      }
    },
    [apiBase]
  );

  const handleDragEnd = useCallback(
    (newPos: Pos) => {
      if (!pos) return;
      const clamped = clampPosToViewport(
        newPos,
        viewportWidth,
        viewportHeight
      );
      setPos(clamped);
      setIsDragging(false);
      void persistPos(clamped);
    },
    [pos, viewportWidth, viewportHeight, persistPos]
  );

  // ---------- RECAP FETCH (session-aware) ----------

  const fetchRecap = useCallback(
    async (force: boolean) => {
      if (!apiBase) return;
      setRecapStatus("loading");

      // Flush current active viewing time for this session
      await flushActiveTimeNow();

      const params = new URLSearchParams();
      if (force) params.set("force", "true");
      params.set("_ts", Date.now().toString()); // cache-buster

      try {
        const res = await fetch(
          `${apiBase}/session-recap?${params.toString()}`,
          { cache: "no-store" }
        );
        if (!res.ok) {
          setRecapStatus("error");
          return;
        }
        const data = await res.json();
        const recap = data.recap || "No recap available yet.";
        const updatedAt =
          typeof data.updated_at === "number" ? data.updated_at : null;

        setRecapText(recap);
        setRecapUpdatedAt(updatedAt);
        setRecapStatus("ready");
      } catch {
        setRecapStatus("error");
      }
    },
    [apiBase, flushActiveTimeNow]
  );

  // ---------- SINGLE BUTTON: START or RECAP+END ----------

  const handleSessionButtonClick = useCallback(async () => {
    if (!apiBase) return;

    // CASE 1: No session yet → start a new session
    if (!sessionActive) {
      try {
        const res = await fetch(`${apiBase}/session-start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        if (!res.ok) {
          console.warn("session-start failed", res.status);
          return;
        }
        // We don't need anything from the response
        setSessionActive(true);
        lastActiveStartRef.current = Date.now() / 1000;
        setRecapStatus("idle");
        setRecapText(null);
      } catch (err) {
        console.warn("session-start error", err);
      }
      return;
    }

    // CASE 2: Session running → recap + end session
    setIsRecapOpen(true);
    await fetchRecap(true);

    // Frontend: mark session as ended
    setSessionActive(false);
  }, [apiBase, sessionActive, fetchRecap]);

  if (!pos) {
    return null;
  }

  const panelPos = computePanelPosition(pos, viewportWidth, viewportHeight);

  return (
    <>
      <Sprite
        name="ghost"
        left={pos.left}
        bottom={pos.bottom}
        size={SPRITE_SIZE}
        staticBase={staticBase}
        onPositionChange={(newPos) => {
          setPos(
            clampPosToViewport(newPos, viewportWidth, viewportHeight)
          );
        }}
        onClick={() => {
          if (isDragging) return;
          setIsMenuOpen((prev) => !prev);
        }}
        onDragStart={() => setIsDragging(true)}
        onDragEnd={handleDragEnd}
      />

      {!commentViewed &&
        commentStatus === "done" &&
        comment && (
          <IdeaSprite
            name="idea"
            left={pos.left + (SPRITE_SIZE - IDEA_SIZE) / 2}
            bottom={pos.bottom + SPRITE_SIZE + 8}
            size={IDEA_SIZE}
            staticBase={staticBase}
            comment={comment}
            onMouseLeave={() => setCommentViewed(true)}
          />
        )}

      {isMenuOpen && (
        <div
          className="ai-sprite-menu"
          style={{
            position: "fixed",
            left: pos.left + SPRITE_SIZE + 8,
            bottom:
              pos.bottom + SPRITE_SIZE / 2 - RECAP_ICON_SIZE / 2,
            zIndex: 2147483647,
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <MenuButton
            ariaLabel={
              sessionActive
                ? "Generate recap and end session"
                : "Start session"
            }
            onClick={(e) => {
              e.stopPropagation();
              setIsMenuOpen(false);
              void handleSessionButtonClick();
            }}
            content={sessionActive ? "📝" : "▶️"}
          />

          <MenuButton
            ariaLabel="Regenerate page comment"
            onClick={(e) => {
              e.stopPropagation();
              setIsMenuOpen(false);
              void fetchComment(true);
            }}
            content="💡"
          />
        </div>
      )}

      {/* Session Recap panel */}
      {isRecapOpen && (
        <PanelFrame
          style={{
            position: "fixed",
            left: panelPos.left,
            bottom: panelPos.bottom,
            width: 380,
            maxHeight: 480,
            zIndex: 2147483647,
          }}
          onClose={() => setIsRecapOpen(false)}
          content={
            recapStatus === "loading"
              ? "Thinking about what you've been up to…"
              : recapStatus === "error"
              ? "I couldn't fetch your recap. Try again."
              : recapText ||
                "Click ▶️ to start a session, then 📝 to get a recap."
          }
        />
      )}
    </>
  );
};
