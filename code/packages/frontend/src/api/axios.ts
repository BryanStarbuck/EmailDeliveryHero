import axios from "axios"
import { logger } from "@/lib/logger"

declare module "axios" {
  export interface AxiosRequestConfig {
    _authRetried?: boolean
  }
}

/**
 * Auth bridge: the @auth/react SDK hooks only work inside React, so <AuthBridge> registers the
 * active session's getToken/reloadSession here for the axios layer (which lives outside the React
 * tree). We never mint, cache, parse, or refresh tokens ourselves — the library owns all of that.
 */
type AuthBridge = {
  getToken: (opts?: { template?: string }) => Promise<string | null>
  reloadSession: () => Promise<boolean>
}
let bridge: AuthBridge | null = null
export const registerAuthBridge = (b: AuthBridge) => {
  bridge = b
}

/** Single shared axios instance. `withCredentials` lets the auth session cookie travel on calls. */
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? "/api",
  withCredentials: true,
})

// Request: attach the short-lived JWT from the active OpenAuthFederated session.
api.interceptors.request.use(async (config) => {
  if (!bridge) return config
  try {
    const token = await bridge.getToken()
    if (token) config.headers.Authorization = `Bearer ${token}`
  } catch (err) {
    logger.warn("Failed to attach auth token", err)
  }
  return config
})

// Response: a 401 is usually transient (expired access token). Rehydrate from the persistent
// session cookie and retry ONCE with a fresh token before giving up — never eagerly sign out.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error.response?.status
    const original = error.config
    if (status === 401 && bridge && original && !original._authRetried) {
      original._authRetried = true
      try {
        if (await bridge.reloadSession()) {
          const token = await bridge.getToken()
          if (token) {
            original.headers = original.headers ?? {}
            original.headers.Authorization = `Bearer ${token}`
          }
          return api(original)
        }
      } catch (reloadErr) {
        logger.warn("Session reload after 401 failed", reloadErr)
      }
    }
    return Promise.reject(error)
  },
)
