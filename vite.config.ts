import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        widget: path.resolve(__dirname, "src/widget/main.tsx"),
      },
      output: {
        entryFileNames: "widget.js",
        assetFileNames: (assetInfo) => {
          // If it's CSS for the widget entry, force name:
          if (assetInfo.name && assetInfo.name.endsWith(".css")) {
            return "widget.css";
          }
          // otherwise default (or something simple)
          return "assets/[name][extname]";
        },
      },
    },
    outDir: "web_static",
    cssCodeSplit: false, // for a single widget entry, this is fine
  },
});