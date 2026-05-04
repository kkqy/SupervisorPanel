import { request } from './http'
import type { ActionResponse, MeResponse } from '@/types/api'

export function login(username: string, password: string) {
  return request<ActionResponse>('/login', {
    method: 'POST',
    json: { username, password },
  })
}

export function getMe() {
  return request<MeResponse>('/api/me')
}

export function changePassword(currentPassword: string, newPassword: string) {
  return request<ActionResponse>('/account/password', {
    method: 'POST',
    json: {
      current_password: currentPassword,
      new_password: newPassword,
    },
  })
}
