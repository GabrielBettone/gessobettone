/**
 * Supabase Auth REST client for the gradual PocketBase migration.
 *
 * This module is deliberately not wired into AuthContext yet. Do not switch the
 * app to Supabase Auth until the data services have also been migrated.
 * It only uses the public/publishable key; authorization is enforced by Supabase.
 */

import { supabaseAuthRequest, SupabaseRequestError } from '@/lib/supabase/client'

export interface SupabaseAuthUser {
  id: string
  email?: string
  phone?: string
  user_metadata?: Record<string, unknown>
  app_metadata?: Record<string, unknown>
  aud?: string
  role?: string
  created_at?: string
  updated_at?: string
}

export interface SupabaseAuthSession {
  access_token: string
  token_type: string
  expires_in: number
  expires_at: number
  refresh_token: string
  user: SupabaseAuthUser
}

export type SupabaseAuthEvent =
  | 'INITIAL_SESSION'
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED'
  | 'SIGNED_UP'
  | 'PASSWORD_RECOVERY'

export type SupabaseOtpType =
  | 'signup'
  | 'invite'
  | 'magiclink'
  | 'recovery'
  | 'email_change'
  | 'email'
  | 'sms'
  | 'phone_change'
  | 'reauthentication'

export interface SupabaseAuthResult {
  user: SupabaseAuthUser | null
  session: SupabaseAuthSession | null
}

type AuthListener = (event: SupabaseAuthEvent, session: SupabaseAuthSession | null) => void

interface AuthPayload {
  access_token?: string
  token_type?: string
  expires_in?: number
  expires_at?: number
  refresh_token?: string
  user?: SupabaseAuthUser | null
  id?: string
  email?: string
  [key: string]: unknown
}

const STORAGE_KEY = 'gesso-bettone.supabase.auth'
const REFRESH_MARGIN_SECONDS = 60
const listeners = new Set<AuthListener>()
let refreshInFlight: Promise<SupabaseAuthSession | null> | null = null
let volatileSession: SupabaseAuthSession | null = null

function browserStorage(): Storage | null {
  if (typeof window === 'undefined') return null
  try {
    return window.localStorage
  } catch {
    return null
  }
}

function normalizeSession(
  payload: AuthPayload,
  fallbackUser?: SupabaseAuthUser,
): SupabaseAuthSession | null {
  const user = payload.user || fallbackUser
  if (!payload.access_token || !payload.refresh_token || !user) return null

  const expiresIn = Number(payload.expires_in || 3600)
  const expiresAt = Number(payload.expires_at || Math.floor(Date.now() / 1000) + expiresIn)

  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    token_type: payload.token_type || 'bearer',
    expires_in: expiresIn,
    expires_at: expiresAt,
    user,
  }
}

function readStoredSession(): SupabaseAuthSession | null {
  const storage = browserStorage()
  if (!storage) return volatileSession
  try {
    const raw = storage.getItem(STORAGE_KEY)
    if (!raw) return volatileSession
    const parsed = JSON.parse(raw) as AuthPayload
    return normalizeSession(parsed) || volatileSession
  } catch {
    return volatileSession
  }
}

function writeStoredSession(session: SupabaseAuthSession): void {
  volatileSession = session
  const storage = browserStorage()
  if (!storage) return
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify(session))
  } catch {
    // Storage may be blocked or full; keep the session in memory for the current tab.
  }
}

function clearStoredSession(): void {
  volatileSession = null
  const storage = browserStorage()
  if (!storage) return
  try {
    storage.removeItem(STORAGE_KEY)
  } catch {
    // A blocked storage API must not prevent a user from signing out in memory.
  }
}

function emit(event: SupabaseAuthEvent, session: SupabaseAuthSession | null): void {
  listeners.forEach((listener) => listener(event, session))
}

function withJsonBody(body: Record<string, unknown>): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }
}

async function refreshSession(
  existing: SupabaseAuthSession,
): Promise<SupabaseAuthSession | null> {
  if (refreshInFlight) return refreshInFlight

  refreshInFlight = (async () => {
    try {
      const payload = await supabaseAuthRequest<AuthPayload>(
        'token?grant_type=refresh_token',
        withJsonBody({ refresh_token: existing.refresh_token }),
      )
      const refreshed = normalizeSession(payload, existing.user)
      if (!refreshed) {
        clearStoredSession()
        emit('SIGNED_OUT', null)
        return null
      }
      writeStoredSession(refreshed)
      emit('TOKEN_REFRESHED', refreshed)
      return refreshed
    } catch (error) {
      if (error instanceof SupabaseRequestError && (error.status === 400 || error.status === 401)) {
        clearStoredSession()
        emit('SIGNED_OUT', null)
        return null
      }
      // Keep the current session if the error may be temporary (e.g. a network outage).
      throw error
    } finally {
      refreshInFlight = null
    }
  })()

  return refreshInFlight
}

/** Return the persisted session and refresh it shortly before it expires. */
export async function getSupabaseSession(): Promise<SupabaseAuthSession | null> {
  const session = readStoredSession()
  if (!session) return null

  const secondsLeft = session.expires_at - Math.floor(Date.now() / 1000)
  if (secondsLeft <= REFRESH_MARGIN_SECONDS) return refreshSession(session)
  return session
}

/** Fetch the current user from the Auth service instead of trusting cached user data. */
export async function getSupabaseUser(): Promise<SupabaseAuthUser | null> {
  const session = await getSupabaseSession()
  if (!session) return null
  return supabaseAuthRequest<SupabaseAuthUser>('user', { method: 'GET' }, session.access_token)
}

export function onSupabaseAuthStateChange(listener: AuthListener): () => void {
  listeners.add(listener)
  let active = true

  // Notify this subscriber of the initial stored session without blocking the caller.
  void getSupabaseSession()
    .then((session) => {
      if (active) listener('INITIAL_SESSION', session)
    })
    .catch(() => {
      if (active) listener('INITIAL_SESSION', readStoredSession())
    })

  const storage = browserStorage()
  const handleStorage = (event: StorageEvent) => {
    if (!active || event.key !== STORAGE_KEY) return
    if (!event.newValue) {
      volatileSession = null
    } else {
      try {
        volatileSession = normalizeSession(JSON.parse(event.newValue) as AuthPayload)
      } catch {
        volatileSession = null
      }
    }
    const session = readStoredSession()
    listener(session ? 'TOKEN_REFRESHED' : 'SIGNED_OUT', session)
  }
  if (typeof window !== 'undefined') window.addEventListener('storage', handleStorage)

  return () => {
    active = false
    listeners.delete(listener)
    if (typeof window !== 'undefined') window.removeEventListener('storage', handleStorage)
  }
}

function payloadUser(payload: AuthPayload, session: SupabaseAuthSession | null): SupabaseAuthUser | null {
  if (payload.user) return payload.user
  if (typeof payload.id === 'string') {
    return {
      id: payload.id,
      email: typeof payload.email === 'string' ? payload.email : undefined,
    }
  }
  return session?.user || null
}

export async function signInWithSupabasePassword(
  email: string,
  password: string,
): Promise<SupabaseAuthResult> {
  const payload = await supabaseAuthRequest<AuthPayload>(
    'token?grant_type=password',
    withJsonBody({ email: email.trim(), password }),
  )
  const session = normalizeSession(payload)
  if (session) {
    writeStoredSession(session)
    emit('SIGNED_IN', session)
  }
  return { user: payloadUser(payload, session), session }
}

export async function signUpWithSupabasePassword(
  name: string,
  email: string,
  password: string,
  redirectTo?: string,
): Promise<SupabaseAuthResult> {
  const query = redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : ''
  const payload = await supabaseAuthRequest<AuthPayload>(
    `signup${query}`,
    withJsonBody({ email: email.trim(), password, data: { name: name.trim() } }),
  )
  const session = normalizeSession(payload)
  if (session) {
    writeStoredSession(session)
    emit('SIGNED_UP', session)
  } else {
    emit('SIGNED_UP', null)
  }
  return { user: payload.user || session?.user || null, session }
}

export async function signOutFromSupabase(): Promise<void> {
  const session = readStoredSession()
  // Clear the local session even if the network is unavailable.
  clearStoredSession()
  emit('SIGNED_OUT', null)

  if (!session) return
  try {
    await supabaseAuthRequest<void>(
      'logout',
      { method: 'POST' },
      session.access_token,
    )
  } catch (error) {
    // A stale/expired token is already logged out locally; other failures are surfaced.
    if (!(error instanceof SupabaseRequestError) || (error.status !== 401 && error.status !== 403)) {
      throw error
    }
  }
}

export async function requestSupabasePasswordReset(
  email: string,
  redirectTo?: string,
): Promise<void> {
  const query = redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : ''
  await supabaseAuthRequest<void>(
    `recover${query}`,
    withJsonBody({ email: email.trim() }),
  )
}

/** Verify an email/recovery token hash supplied by the configured Supabase email template. */
export async function verifySupabaseOtp(
  tokenHash: string,
  type: SupabaseOtpType,
  redirectTo?: string,
): Promise<SupabaseAuthResult> {
  const query = redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : ''
  const payload = await supabaseAuthRequest<AuthPayload>(
    `verify${query}`,
    withJsonBody({ token_hash: tokenHash.trim(), type }),
  )
  const session = normalizeSession(payload)
  if (session) {
    writeStoredSession(session)
    emit(type === 'recovery' ? 'PASSWORD_RECOVERY' : 'SIGNED_IN', session)
  }
  return { user: payload.user || session?.user || null, session }
}

export async function updateSupabaseUser(
  changes: { password?: string; email?: string; data?: Record<string, unknown> },
): Promise<SupabaseAuthUser> {
  const session = await getSupabaseSession()
  if (!session) throw new Error('Sessão expirada. Entre novamente.')

  const user = await supabaseAuthRequest<SupabaseAuthUser>(
    'user',
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(changes),
    },
    session.access_token,
  )
  const updated = { ...session, user }
  writeStoredSession(updated)
  emit('USER_UPDATED', updated)
  return user
}

/**
 * Complete an implicit-flow callback (access_token/refresh_token in the URL hash).
 * The user profile is fetched from Auth before the new session is persisted.
 */
export async function acceptSupabaseSessionFromUrl(): Promise<{
  session: SupabaseAuthSession | null
  type: string | null
}> {
  if (typeof window === 'undefined') return { session: null, type: null }
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const accessToken = params.get('access_token')
  const refreshToken = params.get('refresh_token')
  const expiresIn = Number(params.get('expires_in') || 3600)
  const type = params.get('type')
  if (!accessToken || !refreshToken) return { session: null, type }

  const user = await supabaseAuthRequest<SupabaseAuthUser>('user', { method: 'GET' }, accessToken)
  const session: SupabaseAuthSession = {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: params.get('token_type') || 'bearer',
    expires_in: expiresIn,
    expires_at: Number(params.get('expires_at') || Math.floor(Date.now() / 1000) + expiresIn),
    user,
  }
  writeStoredSession(session)
  const event: SupabaseAuthEvent = type === 'recovery' ? 'PASSWORD_RECOVERY' : 'SIGNED_IN'
  emit(event, session)
  return { session, type }
}
