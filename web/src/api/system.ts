import { request } from './http'
import type { ActionResponse, SystemStatusResponse } from '@/types/api'

export function getSystemStatus() {
  return request<SystemStatusResponse>('/api/system/status')
}

export function restartSupervisor() {
  return request<ActionResponse>('/api/system/supervisor/restart', {
    method: 'POST',
  })
}
