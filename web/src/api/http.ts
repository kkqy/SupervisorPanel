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

export interface UploadProgress {
  loaded: number
  total: number
  percent: number
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

export function uploadForm<T>(url: string, body: FormData, onProgress?: (progress: UploadProgress) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.withCredentials = true
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest')

    xhr.upload.onprogress = (event) => {
      const total = event.lengthComputable ? event.total : 0
      const percent = total > 0 ? Math.min(100, Math.round((event.loaded / total) * 100)) : 0
      onProgress?.({ loaded: event.loaded, total, percent })
    }

    xhr.onload = () => {
      const data = parseJSONText(xhr.responseText)
      if (xhr.status < 200 || xhr.status >= 300 || (isEnvelope(data) && data.ok === false)) {
        const message = isObject(data) && 'message' in data ? String(data.message) : '请求失败'
        reject(new ApiError(message, xhr.status, data))
        return
      }
      resolve(data as T)
    }
    xhr.onerror = () => reject(new Error('网络请求失败'))
    xhr.onabort = () => reject(new Error('上传已取消'))
    xhr.send(body)
  })
}

function parseJSONText(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return {}
  }
}

function isEnvelope(value: unknown): value is { ok: boolean } {
  return isObject(value) && 'ok' in value && typeof value.ok === 'boolean'
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object'
}
