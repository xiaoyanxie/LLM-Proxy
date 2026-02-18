// src/widget/Sprite.tsx
import React, { useEffect, useRef, useState } from "react";

interface SpriteProps {
  name: string;
  left: number;
  bottom: number;
  onPositionChange: (pos: { left: number; bottom: number }) => void;
  onClick: () => void;
  onDragStart?: () => void;
  onDragEnd?: (pos: { left: number; bottom: number }) => void;
  onHoverChange?: (hovered: boolean) => void;
  staticBase: string;
  size?: number;
}

const CLICK_MOVE_THRESHOLD = 4;

export const Sprite: React.FC<SpriteProps> = ({
  name,
  left,
  bottom,
  onPositionChange,
  onClick,
  onDragStart,
  onDragEnd,
  onHoverChange,
  staticBase,
  size = 64,
}) => {
  const [dragging, setDragging] = useState(false);

  const dragStart = useRef<{
    x: number;
    y: number;
    left: number;
    bottom: number;
  } | null>(null);

  const movedRef = useRef(false);
  const currentPosRef = useRef({ left, bottom });

  useEffect(() => {
    currentPosRef.current = { left, bottom };
  }, [left, bottom]);

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!dragging || !dragStart.current) return;

      const dx = e.clientX - dragStart.current.x;
      const dy = e.clientY - dragStart.current.y;

      if (!movedRef.current) {
        if (
          Math.abs(dx) > CLICK_MOVE_THRESHOLD ||
          Math.abs(dy) > CLICK_MOVE_THRESHOLD
        ) {
          movedRef.current = true;
          onDragStart?.();
        }
      }

      onPositionChange({
        left: dragStart.current.left + dx,
        bottom: dragStart.current.bottom - dy,
      });
    }

    function onUp() {
      if (!dragStart.current) return;

      setDragging(false);
      dragStart.current = null;

      const finalPos = currentPosRef.current;

      if (movedRef.current) {
        onDragEnd?.(finalPos);
      } else {
        onClick();
      }

      movedRef.current = false;
    }

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [dragging, onPositionChange, onClick, onDragStart, onDragEnd]);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, left, bottom };
    movedRef.current = false;
    e.preventDefault();
  };

  const avatarUrl = `${staticBase.replace(/\/$/, "")}/${name}.png`;

  return (
    <div
      className="ai-sprite"
      style={{ left, bottom, width: size, height: size }}
      onMouseDown={handleMouseDown}
      onMouseEnter={() => onHoverChange?.(true)}
      onMouseLeave={() => onHoverChange?.(false)}
    >
      <img src={avatarUrl} className="ai-sprite-img" alt="" aria-hidden="true" />
    </div>
  );
};
