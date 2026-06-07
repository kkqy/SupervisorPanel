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
            <el-button type="primary" :loading="savingConfig" @click="saveConfig">保存参数和运行用户</el-button>
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
      @edit-file="editFile"
    />

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
  deleteDir,
  deleteFile,
  deleteProject,
  getProject,
  projectAction,
  renameEntry,
  saveProjectConfig,
  uploadProjectFiles,
} from '@/api/projects'
import { errorMessage } from '@/api/http'
import type { UploadProgress } from '@/api/http'
import type { DirEntry, ProjectDetailResponse } from '@/types/api'

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
const config = reactive({ entryFile: '', args: '', runUser: '' })

onMounted(() => {
  void loadDetail()
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
  } catch (error) {
    ElMessage.error(errorMessage(error, '加载项目失败'))
  } finally {
    loading.value = false
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
</script>
