import React from "react";

interface IdeaSpriteProps {
  name: string;
  left: number;
  bottom: number;
  staticBase: string;
  size?: number;
  comment: string;
  onMouseLeave: () => void;
}

export const IdeaSprite: React.FC<IdeaSpriteProps> = ({
  name,
  left,
  bottom,
  staticBase,
  size = 32,
  comment,
  onMouseLeave,
}) => {
  const avatarUrl = `${staticBase.replace(/\/$/, "")}/${name}.png`;

  return (
    <div
      className="ai-idea"
      style={{ left, bottom, width: size, height: size }}
      onMouseLeave={onMouseLeave}
    >
      <img src={avatarUrl} className="ai-idea-img" alt="" aria-hidden="true" />
      <div className="ai-idea-panel">
        <div className="ai-idea-panel-inner">{comment}</div>
      </div>
    </div>
  );
};
