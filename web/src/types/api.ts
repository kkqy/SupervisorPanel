export interface ApiEnvelope {
  ok: boolean
  message?: string
}

export interface AdminInfo {
  id: number
  username: string
}

export interface Project {
  id: number
  name: string
  slug: string
  path: string
  entry_file: string
  args: string
  run_user: string
  created_at: string
  updated_at: string
  status: string
  status_text: string
}

export interface DirEntry {
  name: string
  path: string
  is_dir: boolean
  editable: boolean
  is_current: boolean
  size: number
  owner: string
  modified_at: string
}

export interface BreadcrumbItem {
  name: string
  dir: string
}

export interface ProjectsResponse extends ApiEnvelope {
  projects: Project[]
  projects_dir: string
}

export interface ProjectDetailResponse extends ApiEnvelope {
  project: Project
  files: string[]
  entries: DirEntry[]
  current_dir: string
  parent_dir: string
  breadcrumbs: BreadcrumbItem[]
  current_entry: string
  current_args: string
  status: string
  status_text: string
}

export interface StatusesResponse extends ApiEnvelope {
  statuses: Record<string, string>
}

export interface CpuSnapshot {
  usage_percent: number
}

export interface MemorySnapshot {
  total_bytes: number
  used_bytes: number
  available_bytes: number
  usage_percent: number
}

export interface DiskSnapshot {
  path: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  usage_percent: number
}

export interface SystemSnapshot {
  cpu: CpuSnapshot
  memory: MemorySnapshot
  disk: DiskSnapshot
  collected_at: string
}

export interface SystemStatusResponse extends ApiEnvelope {
  system: SystemSnapshot
}

export interface UpdateStatus {
  enabled: boolean
  current_version: string
  latest_version: string
  update_available: boolean
  release_url: string
  checked_at?: string
  error: string
  checking: boolean
  upgrading: boolean
  upgrade_message: string
  upgrade_started_at?: string
  upgrade_finished_at?: string
}

export interface UpdateStatusResponse extends ApiEnvelope {
  update: UpdateStatus
}

export interface UpdateActionResponse extends ApiEnvelope {
  update: UpdateStatus
}

export interface ProcessSnapshot {
  status: string
  status_text: string
  pid: number
  cpu_percent: number
  memory_bytes: number
  memory_percent: number
  listen_ports: number[]
  connection_count: number
  available: boolean
  message: string
}

export interface ProcessStatusesResponse extends ApiEnvelope {
  processes: Record<string, ProcessSnapshot>
}

export interface ActionResponse extends ApiEnvelope {
  status?: string
  project_id?: number
  current_entry?: string
  mtime_nano?: string
  count?: number
  received_count?: number
  saved_count?: number
  failed_count?: number
  failed_summary?: string
}

export interface LogsResponse extends ApiEnvelope {
  project: Project
  logs: string
  lines: number
  start_offset: number
  log_path: string
}

export interface FileContentResponse extends ApiEnvelope {
  project: Project
  path: string
  content: string
  mtime_nano: string
  max_size: number
}

export interface MeResponse extends ApiEnvelope {
  admin: AdminInfo
}
