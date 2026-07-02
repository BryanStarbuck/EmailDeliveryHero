import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The UI WebApp always runs on :4444 (override with WEBAPP_PORT). strictPort fails loudly rather
// than silently drifting to another port. See pm/overview.mdx "Key facts".
const WEBAPP_PORT = Number(process.env.WEBAPP_PORT ?? 4444);
const API_PORT = Number(process.env.API_PORT ?? 9312);
// Where the backend lives. "localhost" for local dev; docker-compose sets API_HOST=backend so the
// preview server inside the frontend container proxies /api to the backend service (pm/engineering.mdx §9).
const API_HOST = process.env.API_HOST ?? "localhost";

export default defineConfig({
	plugins: [react(), tailwindcss()],
	resolve: {
		alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
	},
	server: {
		port: WEBAPP_PORT,
		strictPort: true,
		fs: {
			// pm/left_bar.yaml (the single source of truth for the nav) lives outside the frontend
			// package, at the EmailDeliveryHero repo root. Grant the dev server read access to the whole
			// tree so config/left_bar.ts can import that master file directly (no drift-prone copy).
			allow: [fileURLToPath(new URL("../../../", import.meta.url))],
		},
		proxy: {
			// Dev: proxy API + the embedded auth API to the NestJS backend so cookies/origin stay simple.
			"/api": { target: `http://${API_HOST}:${API_PORT}`, changeOrigin: true },
		},
	},
	preview: { port: WEBAPP_PORT, strictPort: true },
	test: { environment: "jsdom", globals: true },
});
