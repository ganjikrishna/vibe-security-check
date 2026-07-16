import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/server", { recursive: true });
mkdirSync("dist/client", { recursive: true });
mkdirSync("dist/.openai", { recursive: true });
const indexHtml = readFileSync("public/index.html", "utf8");
const workerSource = readFileSync("worker/index.js", "utf8");
writeFileSync("dist/server/index.js", `globalThis.__VIBE_INDEX_HTML__=${JSON.stringify(indexHtml)};\n${workerSource}`);
cpSync("public", "dist/client", { recursive: true });
rmSync("dist/client/index.html", { force: true });
cpSync(".openai/hosting.json", "dist/.openai/hosting.json");
console.log("Built Vibe Security Check web app");
