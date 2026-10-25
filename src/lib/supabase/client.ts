/**
 * Camada HTTP mínima para a API Data/Storage do Supabase.
 *
 * Esta camada fica isolada até os módulos serem migrados gradualmente do PocketBase.
 * Não usa service_role no browser: somente uma chave pública/publishable e, quando
 * necessário, o access token do usuário autenticado. O Row Level Security continua
 * sendo a fronteira de autorização do banco.
 */

export interface SupabaseErrorPayload {
  message?: string
  error?: string
  error_description?: string
  msg?: string
  hint?: string
  details?: string
  code?: string
}

export class SupabaseRequestError extends Error {
  readonly status: number
  readonly code?: string
  readonly details?: string
  readonly hint?: string

  constructor(status: number, payload: SupabaseErrorPayload, fallbackMessage: string) {
    super(payload.message || payload.msg || payload.error_description || payload.error || fallbackMessage)
    this.name = 'SupabaseRequestError'
    this.status = status
    this.code = payload.code
    this.details = payload.details
    this.hint = payload.hint
  }
}

export interface SupabaseFilter {
  column: string
  operator?: 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'like' | 'ilike' | 'is' | 'in'
  value: string | number | boolean | null | Array<string | number>
}

export interface SupabaseSelectOptions {
  columns?: string
  filters?: SupabaseFilter[]
  order?: { column: string; ascending?: boolean; nullsFirst?: boolean }[]
  limit?: number
  offset?: number
  accessToken?: string
}

export interface SupabaseWriteOptions {
  accessToken?: string
  returning?: 'minimal' | 'representation'
}

interface SupabaseConfiguration {
  url: string
  publicKey: string
}

function readConfiguration(): SupabaseConfiguration {
  const env = import.meta.env as Record<string, string | undefined>
  const url = (env.VITE_SUPABASE_URL || '').trim().replace(/\/+$/, '')
  const publicKey = (
    env.VITE_SUPABASE_PUBLISHABLE_KEY ||
    env.VITE_SUPABASE_ANON_KEY ||
    ''
  ).trim()

  return { url, publicKey }
}

export function isSupabaseConfigured(): boolean {
  const { url, publicKey } = readConfiguration()
  return /^https:\/\//i.test(url) && Boolean(publicKey)
}

function getConfiguration(): SupabaseConfiguration {
  const config = readConfiguration()
  if (!config.url || !config.publicKey) {
    throw new Error(
      'Supabase ainda não está configurado. Defina VITE_SUPABASE_URL e VITE_SUPABASE_PUBLISHABLE_KEY na configuração da aplicação.',
    )
  }
  if (!/^https:\/\//i.test(config.url)) {
    throw new Error('VITE_SUPABASE_URL precisa ser uma URL HTTPS válida.')
  }
  return config
}

function getHeaders(accessToken?: string, extra?: HeadersInit): Headers {
  const { publicKey } = getConfiguration()
  const headers = new Headers(extra)
  headers.set('apikey', publicKey)
  headers.set('Authorization', `Bearer ${accessToken || publicKey}`)
  return headers
}

async function parseError(response: Response): Promise<SupabaseRequestError> {
  let payload: SupabaseErrorPayload = {}
  try {
    payload = (await response.json()) as SupabaseErrorPayload
  } catch {
    // Algumas respostas de proxy podem não conter JSON.
  }
  return new SupabaseRequestError(
    response.status,
    payload,
    `Falha na API do Supabase (HTTP ${response.status}).`,
  )
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  accessToken?: string,
): Promise<T> {
  const { url } = getConfiguration()
  const headers = getHeaders(accessToken, init.headers)
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${url}${path}`, {
    ...init,
    headers,
  })

  if (!response.ok) {
    throw await parseError(response)
  }
  if (response.status === 204) return undefined as T

  const text = await response.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

export async function supabaseAuthRequest<T>(
  path: string,
  init: RequestInit = {},
  accessToken?: string,
): Promise<T> {
  const cleanPath = path.replace(/^\\/+/, '')
  return request<T>(`/auth/v1/${cleanPath}`, init, accessToken)
}

function buildQuery(options: SupabaseSelectOptions = {}): URLSearchParams {
  const query = new URLSearchParams()
  query.set('select', options.columns || '*')

  for (const filter of options.filters || []) {
    const operator = filter.operator || 'eq'
    let value: string
    if (filter.value === null) {
      value = 'null'
    } else if (Array.isArray(filter.value)) {
      value = `(${filter.value.map((item) => JSON.stringify(String(item))).join(',')})`
    } else {
      value = String(filter.value)
    }
    query.append(filter.column, `${operator}.${value}`)
  }

  if (options.order?.length) {
    query.set(
      'order',
      options.order
        .map(({ column, ascending = true, nullsFirst }) => {
          const nullOrder = nullsFirst === undefined ? '' : nullsFirst ? '.nullsfirst' : '.nullslast'
          return `${column}.${ascending ? 'asc' : 'desc'}${nullOrder}`
        })
        .join(','),
    )
  }
  if (options.limit !== undefined) query.set('limit', String(Math.max(0, options.limit)))
  if (options.offset !== undefined) query.set('offset', String(Math.max(0, options.offset)))
  return query
}

export async function supabaseSelect<T>(
  table: string,
  options: SupabaseSelectOptions = {},
): Promise<T[]> {
  const safeTable = encodeURIComponent(table)
  return request<T[]>(`/rest/v1/${safeTable}?${buildQuery(options).toString()}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  }, options.accessToken)
}

export async function supabaseInsert<T>(
  table: string,
  records: Record<string, unknown> | Record<string, unknown>[],
  options: SupabaseWriteOptions = {},
): Promise<T[]> {
  const prefer = options.returning === 'minimal' ? 'return=minimal' : 'return=representation'
  const result = await request<T[] | undefined>(
    `/rest/v1/${encodeURIComponent(table)}`,
    {
      method: 'POST',
      headers: { Prefer: prefer },
      body: JSON.stringify(records),
    },
    options.accessToken,
  )
  return result || []
}

export async function supabaseUpdate<T>(
  table: string,
  filters: SupabaseFilter[],
  changes: Record<string, unknown>,
  options: SupabaseWriteOptions = {},
): Promise<T[]> {
  const query = buildQuery({ columns: '*', filters })
  const prefer = options.returning === 'minimal' ? 'return=minimal' : 'return=representation'
  const result = await request<T[] | undefined>(
    `/rest/v1/${encodeURIComponent(table)}?${query.toString()}`,
    {
      method: 'PATCH',
      headers: { Prefer: prefer },
      body: JSON.stringify(changes),
    },
    options.accessToken,
  )
  return result || []
}

export async function supabaseDelete(
  table: string,
  filters: SupabaseFilter[],
  options: SupabaseWriteOptions = {},
): Promise<void> {
  const query = buildQuery({ columns: 'id', filters })
  await request<void>(
    `/rest/v1/${encodeURIComponent(table)}?${query.toString()}`,
    { method: 'DELETE', headers: { Prefer: options.returning === 'representation' ? 'return=representation' : 'return=minimal' } },
    options.accessToken,
  )
}

export async function supabaseRpc<T>(
  functionName: string,
  args: Record<string, unknown> = {},
  accessToken?: string,
): Promise<T> {
  return request<T>(
    `/rest/v1/rpc/${encodeURIComponent(functionName)}`,
    { method: 'POST', body: JSON.stringify(args) },
    accessToken,
  )
}

export interface SupabaseUploadResult {
  Key?: string
  path: string
  fullPath?: string
}

export async function supabaseUpload(
  bucket: string,
  path: string,
  file: File | Blob,
  options: { accessToken?: string; contentType?: string; upsert?: boolean } = {},
): Promise<SupabaseUploadResult> {
  const cleanPath = path.split('/').filter(Boolean).map(encodeURIComponent).join('/')
  const headers = new Headers({
    'Content-Type': options.contentType || file.type || 'application/octet-stream',
    'x-upsert': options.upsert ? 'true' : 'false',
  })
  const result = await request<SupabaseUploadResult>(
    `/storage/v1/object/${encodeURIComponent(bucket)}/${cleanPath}`,
    { method: 'POST', headers, body: file },
    options.accessToken,
  )
  return result
}

export function supabasePublicUrl(bucket: string, path: string): string {
  const { url } = getConfiguration()
  const cleanPath = path.split('/').filter(Boolean).map(encodeURIComponent).join('/')
  return `${url}/storage/v1/object/public/${encodeURIComponent(bucket)}/${cleanPath}`
}
