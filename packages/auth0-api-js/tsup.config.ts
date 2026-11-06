import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: [
      "src/index.ts",
      "src/testing.ts",
    ],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
  },
]);