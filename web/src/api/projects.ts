import { request, uploadForm, type UploadProgress } from './http'
import type {
  ActionResponse,
  FileContentResponse,
  LogsResponse,
  ProjectDetailResponse,
  ProjectsResponse,
  StatusesResponse,
} from '@/types/api'

export function getProjects() {
  return request<ProjectsResponse>('/api/projects')
}

export function getProjectStatuses() {
  return request<StatusesResponse>('/api/projects/statuses')
}

export function getProject(projectID: number, dir = '') {
  const params = new URLSearchParams()
  if (dir) params.set('dir', dir)
  const query = params.toString()
  return request<ProjectDetailResponse>(`/api/projects/${projectID}${query ? `?${query}` : ''}`)
}

export function createProject(name: string) {
  return request<ActionResponse>('/projects', {
    method: 'POST',
    json: { name },
  })
}

export function cloneProject(projectID: number, name: string, includeSymlinks: boolean) {
  return request<ActionResponse>(`/projects/${projectID}/clone`, {
    method: 'POST',
    json: { name, include_symlinks: includeSymlinks },
  })
}

export function deleteProject(projectID: number, confirmName: string) {
  return request<ActionResponse>(`/projects/${projectID}/delete`, {
    method: 'POST',
    json: { confirm_name: confirmName },
  })
}

export function projectAction(projectID: number, action: 'start' | 'stop' | 'restart') {
  return request<ActionResponse>(`/projects/${projectID}/action`, {
    method: 'POST',
    json: { action },
  })
}

export function saveProjectConfig(projectID: number, entryFile: string, args: string, runUser: string) {
  return request<ActionResponse>(`/projects/${projectID}/config`, {
    method: 'POST',
    json: {
      entry_file: entryFile,
      args,
      run_user: runUser,
    },
  })
}

export function uploadProjectFiles(
  projectID: number,
  currentDir: string,
  files: Array<{ file: File; path: string }>,
  onProgress?: (progress: UploadProgress) => void,
) {
  const formData = new FormData()
  formData.append('current_dir', currentDir)
  for (const item of files) {
    formData.append('files', item.file, item.path)
    formData.append('rel_paths', item.path)
  }
  return uploadForm<ActionResponse>(`/projects/${projectID}/upload`, formData, onProgress)
}

export function createDir(projectID: number, currentDir: string, name: string) {
  return request<ActionResponse>(`/projects/${projectID}/mkdir`, {
    method: 'POST',
    json: { current_dir: currentDir, name },
  })
}

export function createFile(projectID: number, currentDir: string, name: string) {
  return request<ActionResponse>(`/projects/${projectID}/create-file`, {
    method: 'POST',
    json: { current_dir: currentDir, name },
  })
}

export function renameEntry(projectID: number, relPath: string, newName: string) {
  return request<ActionResponse>(`/projects/${projectID}/rename`, {
    method: 'POST',
    json: { rel_path: relPath, new_name: newName },
  })
}

export function deleteFile(projectID: number, relPath: string) {
  return request<ActionResponse>(`/projects/${projectID}/delete-file`, {
    method: 'POST',
    json: { rel_path: relPath },
  })
}

export function deleteDir(projectID: number, relPath: string) {
  return request<ActionResponse>(`/projects/${projectID}/delete-dir`, {
    method: 'POST',
    json: { rel_path: relPath },
  })
}

export function getLogs(projectID: number, lines: number) {
  return request<LogsResponse>(`/api/projects/${projectID}/logs?lines=${encodeURIComponent(String(lines))}`)
}

export function getFileContent(projectID: number, path: string) {
  return request<FileContentResponse>(`/api/projects/${projectID}/files/content?path=${encodeURIComponent(path)}`)
}

export function saveFileContent(projectID: number, path: string, content: string, mtimeNano: string) {
  return request<ActionResponse>(`/projects/${projectID}/files/edit`, {
    method: 'POST',
    json: { path, content, mtime_nano: mtimeNano },
  })
}

export function downloadURL(projectID: number, path: string, currentDir = '') {
  const params = new URLSearchParams({ path })
  if (currentDir) params.set('dir', currentDir)
  return `/projects/${projectID}/download?${params.toString()}`
}
