import { request } from './http'
import type { ActionResponse, SystemStatusResponse, UpdateActionResponse, UpdateStatusResponse } from '@/types/api'

export function getSystemStatus() {
  return request<SystemStatusResponse>('/api/system/status')
}

export function restartSupervisor() {
  return request<ActionResponse>('/api/system/supervisor/restart', {
    method: 'POST',
  })
}

export function getUpdateStatus() {
  return request<UpdateStatusResponse>('/api/system/update')
}

export function checkForUpdate() {
  return request<UpdateStatusResponse>('/api/system/update/check', {
    method: 'POST',
  })
}

export function upgradePanel() {
  return request<UpdateActionResponse>('/api/system/update/upgrade', {
    method: 'POST',
  })
}
