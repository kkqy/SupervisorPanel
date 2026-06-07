<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">项目列表</h1>
        <p class="page-subtitle">项目目录：<span class="mono">{{ projectsDir || '-' }}</span></p>
      </div>
      <div class="toolbar">
        <el-button @click="loadProjects">刷新</el-button>
        <el-button type="primary" @click="createDialog.visible = true">创建项目</el-button>
      </div>
    </div>

    <el-card shadow="never">
      <el-table v-loading="loading" :data="projects" stripe row-key="id">
        <el-table-column prop="name" label="名称" min-width="180">
          <template #default="{ row }">
            <el-link type="primary" :underline="false" @click="router.push(`/projects/${row.id}`)">{{ row.name }}</el-link>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="130">
          <template #default="{ row }"><StatusTag :status="row.status" :text="row.status_text" /></template>
        </el-table-column>
        <el-table-column label="PID" width="100">
          <template #default="{ row }"><span class="mono">{{ processInfo(row.id)?.pid || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="CPU" width="100">
          <template #default="{ row }">{{ formatPercent(processInfo(row.id)?.cpu_percent) }}</template>
        </el-table-column>
        <el-table-column label="内存" width="120">
          <template #default="{ row }">{{ formatBytes(processInfo(row.id)?.memory_bytes) }}</template>
        </el-table-column>
        <el-table-column label="端口" min-width="140">
          <template #default="{ row }"><span class="mono muted">{{ formatPorts(processInfo(row.id)?.listen_ports) }}</span></template>
        </el-table-column>
        <el-table-column label="连接数" width="100">
          <template #default="{ row }">{{ processInfo(row.id)?.connection_count ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="主程序" min-width="180">
          <template #default="{ row }"><span class="mono muted">{{ row.entry_file || '未配置' }}</span></template>
        </el-table-column>
        <el-table-column prop="run_user" label="运行用户" width="120" />
        <el-table-column prop="updated_at" label="更新时间" min-width="170" />
        <el-table-column label="操作" width="430" fixed="right">
          <template #default="{ row }">
            <div class="toolbar">
              <el-button size="small" @click="router.push(`/projects/${row.id}`)">编辑</el-button>
              <el-button v-if="row.status !== 'RUNNING'" size="small" type="success" @click="runAction(row.id, 'start')">启动</el-button>
              <el-button v-else size="small" type="warning" plain @click="runAction(row.id, 'stop')">停止</el-button>
              <el-button size="small" @click="runAction(row.id, 'restart')">重启</el-button>
              <el-button size="small" @click="openClone(row)">复制</el-button>
              <el-button size="small" type="danger" plain @click="confirmDelete(row)">删除</el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="createDialog.visible" title="创建项目" width="420px">
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="项目名称" required>
          <el-input v-model.trim="createDialog.name" placeholder="例如：order-service" autofocus @keyup.enter="submitCreate" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="createDialog.loading" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="cloneDialog.visible" title="复制项目" width="420px">
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="新项目名称" required>
          <el-input v-model.trim="cloneDialog.name" autofocus @keyup.enter="submitClone" />
        </el-form-item>
        <el-checkbox v-model="cloneDialog.includeSymlinks">复制符号链接</el-checkbox>
      </el-form>
      <template #footer>
        <el-button @click="cloneDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="cloneDialog.loading" @click="submitClone">确认复制</el-button>
      </template>
    </el-dialog>
  </section>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'

import StatusTag from '@/components/StatusTag.vue'
import { cloneProject, createProject, deleteProject, getProjectProcessStatuses, getProjects, projectAction } from '@/api/projects'
import { errorMessage } from '@/api/http'
import type { ProcessSnapshot, Project } from '@/types/api'

const router = useRouter()
const loading = ref(false)
const refreshingStatuses = ref(false)
const projects = ref<Project[]>([])
const projectsDir = ref('')
const processStatuses = ref<Record<string, ProcessSnapshot>>({})
let timer: number | undefined

const createDialog = reactive({ visible: false, name: '', loading: false })
const cloneDialog = reactive({ visible: false, projectID: 0, name: '', includeSymlinks: false, loading: false })

onMounted(() => {
  void loadProjects()
  timer = window.setInterval(() => {
    if (!document.hidden) void refreshStatuses()
  }, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})

async function loadProjects() {
  loading.value = true
  try {
    const result = await getProjects()
    projects.value = result.projects
    projectsDir.value = result.projects_dir
    await refreshStatuses()
  } catch (error) {
    ElMessage.error(errorMessage(error, '加载项目失败'))
  } finally {
    loading.value = false
  }
}

async function refreshStatuses() {
  if (refreshingStatuses.value) return

  refreshingStatuses.value = true
  try {
    const result = await getProjectProcessStatuses()
    processStatuses.value = result.processes
    for (const project of projects.value) {
      const snapshot = processInfo(project.id)
      project.status = snapshot?.status || 'UNKNOWN'
      project.status_text = snapshot?.status_text || statusText(project.status)
    }
  } catch {
    ElMessage.warning('状态刷新失败，稍后重试')
  } finally {
    refreshingStatuses.value = false
  }
}

async function submitCreate() {
  if (!createDialog.name) {
    ElMessage.error('项目名不能为空')
    return
  }
  createDialog.loading = true
  try {
    const result = await createProject(createDialog.name)
    ElMessage.success(result.message || '项目创建成功')
    createDialog.visible = false
    createDialog.name = ''
    await loadProjects()
  } catch (error) {
    ElMessage.error(errorMessage(error, '创建失败'))
  } finally {
    createDialog.loading = false
  }
}

function openClone(project: Project) {
  cloneDialog.projectID = project.id
  cloneDialog.name = `${project.name}-copy`
  cloneDialog.includeSymlinks = false
  cloneDialog.visible = true
}

async function submitClone() {
  if (!cloneDialog.name) {
    ElMessage.error('新项目名称不能为空')
    return
  }
  cloneDialog.loading = true
  try {
    const result = await cloneProject(cloneDialog.projectID, cloneDialog.name, cloneDialog.includeSymlinks)
    ElMessage.success(result.message || '项目复制成功')
    cloneDialog.visible = false
    await loadProjects()
  } catch (error) {
    ElMessage.error(errorMessage(error, '复制失败'))
  } finally {
    cloneDialog.loading = false
  }
}

async function runAction(projectID: number, action: 'start' | 'stop' | 'restart') {
  try {
    const result = await projectAction(projectID, action)
    ElMessage.success(result.message || '操作成功')
    await refreshStatuses()
  } catch (error) {
    ElMessage.error(errorMessage(error, '操作失败'))
  }
}

async function confirmDelete(project: Project) {
  await ElMessageBox.prompt(`请输入项目名 ${project.name} 以确认删除。`, '删除项目', {
    inputPattern: new RegExp(`^${escapeRegExp(project.name)}$`),
    inputErrorMessage: '项目名不匹配',
    confirmButtonText: '删除',
    cancelButtonText: '取消',
    type: 'warning',
  })
  try {
    const result = await deleteProject(project.id, project.name)
    ElMessage.success(result.message || '项目已删除')
    await loadProjects()
  } catch (error) {
    ElMessage.error(errorMessage(error, '删除失败'))
  }
}

function statusText(status: string) {
  switch (status) {
    case 'RUNNING':
      return '运行中'
    case 'STOPPED':
      return '已停止'
    case 'EXITED':
      return '已退出'
    case 'STARTING':
      return '启动中'
    case 'STOPPING':
      return '停止中'
    case 'BACKOFF':
      return '启动失败(重试中)'
    case 'FATAL':
      return '启动失败'
    default:
      return '未知'
  }
}

function processInfo(projectID: number) {
  return processStatuses.value[String(projectID)]
}

function formatPercent(value?: number) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '-'
  return `${value.toFixed(value >= 10 ? 0 : 1)}%`
}

function formatBytes(value?: number) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`
}

function formatPorts(ports?: number[]) {
  return ports?.length ? ports.join(', ') : '-'
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
</script>
