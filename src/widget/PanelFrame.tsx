import React from "react";

interface PanelFrameProps {
  style: React.CSSProperties;
  onClose: () => void;
  content?: String;
}

export const PanelFrame: React.FC<PanelFrameProps> = ({
  style,
  onClose,
  content,
}) => {
  return (
    <div className="ai-panel" style={style}>
      <div className="ai-panel-header">
        <div className="ai-panel-title">Session Recap</div>
        <button className="ai-panel-close" onClick={onClose}>
          ✕
        </button>
      </div>

      <div className="ai-panel-body">
        {content || "Loading session recap..."}
      </div>
    </div>
  );
};