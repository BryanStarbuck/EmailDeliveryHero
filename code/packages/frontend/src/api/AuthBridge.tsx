import { useAuth } from "@auth/react";
import { useEffect } from "react";
import { logger } from "@/lib/logger";
import { registerAuthBridge } from "./axios";

/**
 * Mount once inside <FederatedProvider> to wire the SDK's session into the axios layer.
 * Renders nothing.
 */
export function AuthBridge() {
	const { getToken, reloadSession } = useAuth();
	useEffect(() => {
		try {
			registerAuthBridge({ getToken, reloadSession });
		} catch (err) {
			logger.error("Failed to register auth bridge", err);
		}
	}, [getToken, reloadSession]);
	return null;
}
