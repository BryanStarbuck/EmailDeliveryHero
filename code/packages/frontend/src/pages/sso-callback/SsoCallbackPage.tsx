import { AuthenticateWithRedirectCallback } from "@auth/react";

/**
 * The OAuth/SSO return landing. After Google redirects back, the OpenAuthFederated SDK component
 * completes the handshake (establishes the session) and then routes the user onward. We own no
 * token handling here — the library does it all.
 */
export function SsoCallbackPage() {
	return (
		<div className="flex min-h-screen items-center justify-center text-sm text-[var(--edh-muted)]">
			Completing sign-in…
			<AuthenticateWithRedirectCallback signInForceRedirectUrl="/" />
		</div>
	);
}
