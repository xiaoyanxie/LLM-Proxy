import React from "react";

export interface MenuButtonProps {
  size?: number;
  ariaLabel: string;
  onClick: (e: React.MouseEvent<HTMLButtonElement>) => void;
  children: React.ReactNode;
}

export const MenuButton: React.FC<MenuButtonProps> = ({
  size = 28,
  ariaLabel,
  onClick,
  content,
}) => {
  return (
    <button
      className="ai-recap-icon"
      style={{
        all: "unset",
        width: size,
        height: size,
        borderRadius: "999px",
        background: "rgba(18, 18, 22, 0.96)",
        color: "#f9f9ff",
        fontSize: 11,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "pointer",
        boxShadow: "0 2px 8px rgba(0, 0, 0, 0.4)",
      }}
      onClick={onClick}
      aria-label={ariaLabel}
    >
        <span
            role="img"
            aria-hidden="true"
            style={{ fontSize: 14, lineHeight: 1 }}
        >
            {content}
        </span>
    </button>
  );
};
