export class ApiError extends Error {
  status: number
  data: unknown

  constructor(message: string, status: number, data: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

type RequestOptions = RequestInit & {
  json?: unknown
}

export async function request<T>(url: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  headers.set('X-Requested-With', 'XMLHttpRequest')
  let body = options.body
  if (typeof options.json !== 'undefined') {
    headers.set('Content-Type', 'application/json')
    body = JSON.stringify(options.json)
  }

  const response = await fetch(url, {
    ...options,
    headers,
    body,
    credentials: 'same-origin',
  })

  const data = await parseJSON(response)
  if (!response.ok || (data && typeof data === 'object' && 'ok' in data && data.ok === false)) {
    const message = data && typeof data === 'object' && 'message' in data ? String(data.message) : '请求失败'
    throw new ApiError(message, response.status, data)
  }
  return data as T
}

async function parseJSON(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return {}
  }
}

export function errorMessage(error: unknown, fallback = '操作失败'): string {
  if (error instanceof ApiError) {
    return error.message || fallback
  }
  if (error instanceof Error) {
    return error.message || fallback
  }
  return fallback
}
