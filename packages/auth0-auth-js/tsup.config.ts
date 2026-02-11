import { defineConfig } from "tsup";
import { readFileSync } from "fs";

const packageJson = JSON.parse(readFileSync("./package.json", "utf-8"));

export default defineConfig([
  {
    entry: [
      "src/index.ts",
    ],
    format: ["cjs", "esm"],
    dts: true,
    sourcemap: true,
    define: {
      __AUTH0_AUTH_JS_PACKAGE_NAME__: JSON.stringify(packageJson.name),
      __AUTH0_AUTH_JS_PACKAGE_VERSION__: JSON.stringify(packageJson.version),
    },
  },
]);