/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_API_BASE?: string;
	readonly VITE_AUTH_FRONTEND_API?: string;
	readonly VITE_AUTH_ALLOWED_DOMAINS?: string;
	readonly VITE_AUTH_PUBLISHABLE_KEY?: string;
	readonly VITE_AUTH_SIGN_IN_URL?: string;
	readonly VITE_AUTH_SIGN_UP_URL?: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}

// Allow importing YAML files as raw text (Vite `?raw`).
declare module "*.yaml?raw" {
	const content: string;
	export default content;
}
