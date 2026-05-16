import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: [
      "src/index.ts",
      "src/mcp.ts",
    ],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
  },
]);