// src/content/index.tsx (or whatever your entry is)
import React from "react";
import { createRoot } from "react-dom/client";
import "./widget.css";
import { FloatingWidget } from "./FloatingWidget";

function bootstrap() {
  if (window.top !== window.self) {
    console.log(`${window.name} is not top window, skipping`);
    return;
  }

  let rootEl = document.getElementById("llm-widget-root");
  if (!rootEl) {
    rootEl = document.createElement("div");
    rootEl.id = "llm-widget-root";
    document.body.appendChild(rootEl);
  }

  const root = createRoot(rootEl);
  const config = (window as any).LLM_WIDGET_CONFIG || {};

  root.render(<FloatingWidget config={config} />);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootstrap);
} else {
  bootstrap();
}
