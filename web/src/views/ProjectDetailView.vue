<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">项目：{{ detail?.project.name || '-' }}</h1>
        <p class="page-subtitle">目录：<span class="mono">{{ detail?.project.path || '-' }}</span></p>
      </div>
      <div class="toolbar">
        <StatusTag :status="detail?.status" :text="detail?.status_text" />
        <el-button :loading="loading" @click="loadDetail">刷新</el-button>
        <el-button @click="router.push('/projects')">返回列表</el-button>
        <el-button type="primary" plain @click="router.push(`/projects/${projectID}/logs`)">查看日志</el-button>
      </div>
    </div>

    <el-card shadow="never">
      <template #header>进程资源</template>
      <div class="resource-summary">
        <div class="resource-item">
          <span class="muted">PID</span>
          <span class="mono">{{ processStatus?.pid || '-' }}</span>
        </div>
        <div class="resource-item">
          <span class="muted">CPU</span>
          <span>{{ formatPercent(processStatus?.cpu_percent) }}</span>
        </div>
        <div class="resource-item">
          <span class="muted">内存</span>
          <span>{{ formatBytes(processStatus?.memory_bytes) }}</span>
        </div>
        <div class="resource-item">
          <span class="muted">端口</span>
          <div v-if="processStatus?.listen_ports?.length" class="port-links">
            <el-button
              v-for="port in processStatus.listen_ports"
              :key="port"
              type="primary"
              link
              class="mono"
              @click="openBindDialog(port)"
            >{{ port }}</el-button>
          </div>
          <span v-else class="mono">-</span>
        </div>
        <div class="resource-item">
          <span class="muted">连接数</span>
          <span>{{ processStatus?.connection_count ?? '-' }}</span>
        </div>
      </div>
      <p v-if="processStatus?.message" class="muted">{{ processStatus.message }}</p>
    </el-card>

    <el-card v-loading="loadingBindings" shadow="never">
      <template #header>域名绑定</template>
      <el-table :data="bindings" empty-text="暂无绑定；进程启动后点击上方端口即可绑定域名">
        <el-table-column label="域名" min-width="220">
          <template #default="scope">
            <a :href="`https://${scope.row.domain}`" target="_blank" rel="noopener noreferrer">{{ scope.row.domain }}</a>
          </template>
        </el-table-column>
        <el-table-column prop="port" label="进程端口" width="120" />
        <el-table-column prop="created_at" label="绑定时间" min-width="170" />
        <el-table-column label="操作" width="100" align="right">
          <template #default="scope">
            <el-button
              type="danger"
              link
              :loading="deletingBindingID === scope.row.id"
              @click="confirmDeleteBinding(scope.row)"
            >删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <div class="card-grid">
      <el-card v-loading="loading" shadow="never">
        <template #header>上传文件</template>
        <UploadDropzone :uploading="uploading" :progress="uploadProgress" @upload="uploadFiles" />
        <p class="muted">上传文件夹请直接拖拽到上方区域；按钮支持普通多文件上传。</p>
      </el-card>

      <el-card v-loading="loading" shadow="never">
        <template #header>运行配置</template>
        <el-form label-position="top" @submit.prevent>
          <el-form-item label="当前主程序">
            <el-input v-model="config.entryFile" placeholder="请在文件列表中指定" readonly />
          </el-form-item>
          <el-form-item label="启动参数">
            <el-input v-model="config.args" placeholder="例如：--port 9000 --env prod" />
          </el-form-item>
          <el-form-item label="运行用户">
            <el-input v-model.trim="config.runUser" />
          </el-form-item>
          <div class="toolbar">
            <el-button type="primary" :loading="savingConfig" @click="saveConfig">保存运行配置</el-button>
            <el-button type="success" :loading="runningAction === 'start'" :disabled="!!runningAction && runningAction !== 'start'" @click="runAction('start')">启动</el-button>
            <el-button :loading="runningAction === 'restart'" :disabled="!!runningAction && runningAction !== 'restart'" @click="runAction('restart')">重启</el-button>
            <el-button type="warning" plain :loading="runningAction === 'stop'" :disabled="!!runningAction && runningAction !== 'stop'" @click="runAction('stop')">停止</el-button>
          </div>
        </el-form>
      </el-card>
    </div>

    <FileExplorer
      v-if="detail"
      :project-id="projectID"
      :current-dir="detail.current_dir"
      :parent-dir="detail.parent_dir"
      :breadcrumbs="detail.breadcrumbs"
      :entries="detail.entries"
      :busy-action="explorerBusy?.action"
      :busy-path="explorerBusy?.path"
      @enter-dir="enterDir"
      @create-dir="handleCreateDir"
      @create-file="handleCreateFile"
      @rename="handleRename"
      @delete="handleDeleteEntry"
      @set-entry="setEntry"
      @set-executable="handleSetExecutable"
      @edit-file="editFile"
    />

    <el-dialog v-model="bindDialog.visible" title="绑定域名" width="460px" @closed="bindDialog.domain = ''">
      <el-form label-position="top" @submit.prevent>
        <el-form-item label="进程端口">
          <el-input :model-value="String(bindDialog.port)" readonly />
        </el-form-item>
        <el-form-item label="访问域名">
          <el-input v-model.trim="bindDialog.domain" placeholder="例如：app.example.com" @keyup.enter="submitBinding" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="bindDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="bindDialog.submitting" @click="submitBinding">确认绑定</el-button>
      </template>
    </el-dialog>

    <el-card class="danger-card" shadow="never">
      <template #header>危险操作</template>
      <p class="muted">删除项目会清理项目目录、数据库记录和 Supervisor 配置，无法恢复。</p>
      <el-button type="danger" :loading="deletingProject" @click="confirmDeleteProject">删除项目</el-button>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'

import FileExplorer from '@/components/FileExplorer.vue'
import StatusTag from '@/components/StatusTag.vue'
import UploadDropzone from '@/components/UploadDropzone.vue'
import {
  createDir,
  createFile,
  createProxyBinding,
  deleteDir,
  deleteFile,
  deleteProject,
  deleteProxyBinding,
  getProject,
  getProjectProcessStatuses,
  getProxyBindings,
  projectAction,
  renameEntry,
  saveProjectConfig,
  setFileExecutable,
  uploadProjectFiles,
} from '@/api/projects'
import { errorMessage } from '@/api/http'
import type { UploadProgress } from '@/api/http'
import type { DirEntry, ProcessSnapshot, ProjectDetailResponse, ProxyBinding } from '@/types/api'

const route = useRoute()
const router = useRouter()
const projectID = Number(route.params.id)

const loading = ref(false)
const uploading = ref(false)
const uploadProgress = ref<UploadProgress | null>(null)
const savingConfig = ref(false)
const runningAction = ref<'start' | 'stop' | 'restart' | ''>('')
const deletingProject = ref(false)
const explorerBusy = ref<{ action: string; path?: string } | null>(null)
const detail = ref<ProjectDetailResponse>()
const processStatus = ref<ProcessSnapshot>()
const loadingProcessStatus = ref(false)
const loadingBindings = ref(false)
const deletingBindingID = ref(0)
const bindings = ref<ProxyBinding[]>([])
const config = reactive({ entryFile: '', args: '', runUser: '' })
const bindDialog = reactive({ visible: false, port: 0, domain: '', submitting: false })

onMounted(() => {
  void loadDetail()
  void loadProcessStatus()
})

watch(
  () => route.query.dir,
  () => void loadDetail(),
)

async function loadDetail() {
  loading.value = true
  try {
    const result = await getProject(projectID, currentDirFromRoute())
    detail.value = result
    config.entryFile = result.current_entry
    config.args = result.current_args
    config.runUser = result.project.run_user
    void loadProcessStatus()
    void loadBindings()
  } catch (error) {
    ElMessage.error(errorMessage(error, '加载项目失败'))
  } finally {
    loading.value = false
  }
}

async function loadBindings() {
  loadingBindings.value = true
  try {
    const result = await getProxyBindings(projectID)
    bindings.value = result.bindings
  } catch (error) {
    ElMessage.error(errorMessage(error, '加载域名绑定失败'))
  } finally {
    loadingBindings.value = false
  }
}

function openBindDialog(port: number) {
  bindDialog.port = port
  bindDialog.domain = ''
  bindDialog.visible = true
}

async function submitBinding() {
  if (bindDialog.submitting) return
  if (!bindDialog.domain.trim()) {
    ElMessage.error('请输入域名')
    return
  }
  bindDialog.submitting = true
  try {
    const result = await createProxyBinding(projectID, bindDialog.domain, bindDialog.port)
    ElMessage.success(result.message || '域名绑定成功')
    bindDialog.visible = false
    await loadBindings()
  } catch (error) {
    ElMessage.error(errorMessage(error, '域名绑定失败'))
  } finally {
    bindDialog.submitting = false
  }
}

async function confirmDeleteBinding(binding: ProxyBinding) {
  await ElMessageBox.confirm(`确认删除 ${binding.domain} → 127.0.0.1:${binding.port} 的绑定吗？`, '删除域名绑定', {
    confirmButtonText: '删除',
    cancelButtonText: '取消',
    type: 'warning',
  })
  deletingBindingID.value = binding.id
  try {
    const result = await deleteProxyBinding(projectID, binding.id)
    ElMessage.success(result.message || '域名绑定已删除')
    await loadBindings()
  } catch (error) {
    ElMessage.error(errorMessage(error, '删除域名绑定失败'))
  } finally {
    deletingBindingID.value = 0
  }
}

async function loadProcessStatus() {
  if (loadingProcessStatus.value) return

  loadingProcessStatus.value = true
  try {
    const result = await getProjectProcessStatuses()
    processStatus.value = result.processes[String(projectID)]
  } catch {
    ElMessage.warning('进程资源刷新失败，稍后重试')
  } finally {
    loadingProcessStatus.value = false
  }
}

function currentDirFromRoute() {
  return typeof route.query.dir === 'string' ? route.query.dir : ''
}

function enterDir(dir: string) {
  void router.push({ path: `/projects/${projectID}`, query: dir ? { dir } : {} })
}

async function uploadFiles(files: Array<{ file: File; path: string }>) {
  if (!files.length) {
    ElMessage.error('未获取到可上传文件')
    return
  }
  uploading.value = true
  uploadProgress.value = { loaded: 0, total: files.reduce((sum, item) => sum + item.file.size, 0), percent: 0 }
  try {
    const result = await uploadProjectFiles(projectID, detail.value?.current_dir || '', files, (progress) => {
      uploadProgress.value = progress
    })
    ElMessage.success(result.message || '上传成功')
    await loadDetail()
  } catch (error) {
    ElMessage.error(errorMessage(error, '上传失败'))
  } finally {
    uploading.value = false
    uploadProgress.value = null
  }
}

async function saveConfig() {
  savingConfig.value = true
  try {
    const result = await saveProjectConfig(projectID, config.entryFile, config.args, config.runUser)
    ElMessage.success(result.message || '配置已保存并应用')
    if (result.current_entry) config.entryFile = result.current_entry
    await loadDetail()
  } catch (error) {
    ElMessage.error(errorMessage(error, '保存失败'))
  } finally {
    savingConfig.value = false
  }
}

async function setEntry(path: string) {
  explorerBusy.value = { action: 'set-entry', path }
  try {
    const result = await saveProjectConfig(projectID, path, config.args, config.runUser)
    ElMessage.success(result.message || '主程序已更新并生效')
    config.entryFile = result.current_entry || path
    await loadDetail()
  } catch (error) {
    ElMessage.error(errorMessage(error, '设置主程序失败'))
  } finally {
    explorerBusy.value = null
  }
}

async function runAction(action: 'start' | 'stop' | 'restart') {
  if (runningAction.value) return
  runningAction.value = action
  try {
    const result = await projectAction(projectID, action)
    ElMessage.success(result.message || '操作成功')
    await loadDetail()
  } catch (error) {
    ElMessage.error(errorMessage(error, '操作失败'))
  } finally {
    runningAction.value = ''
  }
}

async function handleCreateDir(name: string, done?: () => void) {
  await runExplorerTask(() => createDir(projectID, detail.value?.current_dir || '', name), '创建文件夹失败', { action: 'create-dir' }, done)
}

async function handleCreateFile(name: string, done?: () => void) {
  await runExplorerTask(() => createFile(projectID, detail.value?.current_dir || '', name), '创建文件失败', { action: 'create-file' }, done)
}

async function handleRename(path: string, name: string, done?: () => void) {
  await runExplorerTask(() => renameEntry(projectID, path, name), '重命名失败', { action: 'rename', path }, done)
}

async function handleDeleteEntry(entry: DirEntry) {
  await runExplorerTask(
    () => (entry.is_dir ? deleteDir(projectID, entry.path) : deleteFile(projectID, entry.path)),
    '删除失败',
    { action: 'delete', path: entry.path },
  )
}

async function handleSetExecutable(entry: DirEntry) {
  await runExplorerTask(
    () => setFileExecutable(projectID, entry.path, !entry.executable),
    '设置执行权限失败',
    { action: 'set-executable', path: entry.path },
  )
}

async function runExplorerTask(
  task: () => Promise<{ message?: string }>,
  fallback: string,
  busy: { action: string; path?: string },
  done?: () => void,
) {
  explorerBusy.value = busy
  try {
    const result = await task()
    ElMessage.success(result.message || '操作成功')
    await loadDetail()
  } catch (error) {
    ElMessage.error(errorMessage(error, fallback))
  } finally {
    explorerBusy.value = null
    done?.()
  }
}

function editFile(path: string) {
  void router.push({ path: `/projects/${projectID}/files/edit`, query: { path } })
}

async function confirmDeleteProject() {
  const name = detail.value?.project.name || ''
  if (!name) return
  await ElMessageBox.prompt(`请输入项目名 ${name} 以确认删除。`, '删除项目', {
    inputPattern: new RegExp(`^${escapeRegExp(name)}$`),
    inputErrorMessage: '项目名不匹配',
    confirmButtonText: '删除',
    cancelButtonText: '取消',
    type: 'warning',
  })
  deletingProject.value = true
  try {
    const result = await deleteProject(projectID, name)
    ElMessage.success(result.message || '项目已删除')
    await router.push('/projects')
  } catch (error) {
    ElMessage.error(errorMessage(error, '删除失败'))
  } finally {
    deletingProject.value = false
  }
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
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

</script>

<style scoped>
.resource-summary {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}

.resource-item {
  display: grid;
  gap: 4px;
  min-width: 0;
}

.port-links {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.port-links .el-button {
  margin: 0;
  padding: 0;
}

.resource-item span:last-child {
  overflow-wrap: anywhere;
}

@media (max-width: 980px) {
  .resource-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 520px) {
  .resource-summary {
    grid-template-columns: 1fr;
  }
}
</style>
