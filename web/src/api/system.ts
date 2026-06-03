import { request } from './http'
import type { ActionResponse } from '@/types/api'

export function restartSupervisor() {
  return request<ActionResponse>('/api/system/supervisor/restart', {
    method: 'POST',
  })
}
