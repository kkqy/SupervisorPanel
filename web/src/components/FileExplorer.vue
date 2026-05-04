<template>
  <el-card shadow="never">
    <template #header>
      <div class="explorer-header">
        <el-breadcrumb separator="/">
          <el-breadcrumb-item v-for="item in breadcrumbs" :key="item.dir || '/'">
            <el-link type="primary" :underline="false" @click="emit('enter-dir', item.dir)">{{ item.name }}</el-link>
          </el-breadcrumb-item>
        </el-breadcrumb>
        <div class="toolbar">
          <el-button v-if="currentDir" @click="emit('enter-dir', parentDir)">上一级</el-button>
          <el-button @click="openCreate('dir')">新建文件夹</el-button>
          <el-button @click="openCreate('file')">新建文件</el-button>
        </div>
      </div>
    </template>

    <el-empty v-if="entries.length === 0" description="暂无文件，请先上传" />
    <el-table v-else :data="entries" row-key="path" stripe>
      <el-table-column label="名称" min-width="260">
        <template #default="{ row }">
          <span class="file-path">{{ row.name }}{{ row.is_dir ? '/' : '' }}</span>
          <el-tag v-if="row.is_current" class="entry-tag" type="warning" size="small">当前主程序</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="类型" width="90">
        <template #default="{ row }">{{ row.is_dir ? '目录' : '文件' }}</template>
      </el-table-column>
      <el-table-column label="路径" min-width="260">
        <template #default="{ row }"><span class="muted mono">{{ row.path }}</span></template>
      </el-table-column>
      <el-table-column label="操作" width="430" fixed="right">
        <template #default="{ row }">
          <div class="toolbar">
            <el-button v-if="row.is_dir" size="small" type="primary" plain @click="emit('enter-dir', row.path)">进入</el-button>
            <el-button v-if="!row.is_dir && !row.is_current" size="small" @click="emit('set-entry', row.path)">设为主程序</el-button>
            <el-button v-if="!row.is_dir && row.editable" size="small" @click="emit('edit-file', row.path)">编辑</el-button>
            <el-button size="small" @click="openRename(row)">重命名</el-button>
            <el-button v-if="!row.is_dir" size="small" tag="a" :href="downloadURL(projectId, row.path, currentDir)">下载</el-button>
            <el-button size="small" type="danger" plain @click="confirmDelete(row)">删除</el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>
  </el-card>

  <el-dialog v-model="createDialog.visible" :title="createDialog.type === 'dir' ? '新建文件夹' : '新建文件'" width="420px">
    <el-form label-position="top" @submit.prevent>
      <el-form-item label="名称">
        <el-input v-model="createDialog.name" autofocus @keyup.enter="submitCreate" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="createDialog.visible = false">取消</el-button>
      <el-button type="primary" @click="submitCreate">创建</el-button>
    </template>
  </el-dialog>

  <el-dialog v-model="renameDialog.visible" title="重命名" width="420px">
    <el-form label-position="top" @submit.prevent>
      <el-form-item label="当前路径">
        <el-text class="mono">{{ renameDialog.path }}</el-text>
      </el-form-item>
      <el-form-item label="新名称">
        <el-input v-model="renameDialog.name" autofocus @keyup.enter="submitRename" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="renameDialog.visible = false">取消</el-button>
      <el-button type="primary" @click="submitRename">确认</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { reactive } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import { downloadURL } from '@/api/projects'
import type { BreadcrumbItem, DirEntry } from '@/types/api'

defineProps<{
  projectId: number
  currentDir: string
  parentDir: string
  breadcrumbs: BreadcrumbItem[]
  entries: DirEntry[]
}>()

const emit = defineEmits<{
  'enter-dir': [dir: string]
  'create-dir': [name: string]
  'create-file': [name: string]
  rename: [path: string, name: string]
  delete: [entry: DirEntry]
  'set-entry': [path: string]
  'edit-file': [path: string]
}>()

const createDialog = reactive({ visible: false, type: 'dir' as 'dir' | 'file', name: '' })
const renameDialog = reactive({ visible: false, path: '', name: '' })

function openCreate(type: 'dir' | 'file') {
  createDialog.type = type
  createDialog.name = ''
  createDialog.visible = true
}

function submitCreate() {
  const name = createDialog.name.trim()
  if (!name) {
    ElMessage.error('名称不能为空')
    return
  }
  if (createDialog.type === 'dir') {
    emit('create-dir', name)
  } else {
    emit('create-file', name)
  }
  createDialog.visible = false
}

function openRename(entry: DirEntry) {
  renameDialog.path = entry.path
  renameDialog.name = entry.name
  renameDialog.visible = true
}

function submitRename() {
  const name = renameDialog.name.trim()
  if (!name) {
    ElMessage.error('新名称不能为空')
    return
  }
  emit('rename', renameDialog.path, name)
  renameDialog.visible = false
}

async function confirmDelete(entry: DirEntry) {
  await ElMessageBox.confirm(`确认删除${entry.is_dir ? '目录' : '文件'} ${entry.path} 吗？`, '危险操作', {
    type: 'warning',
    confirmButtonText: '删除',
    cancelButtonText: '取消',
  })
  emit('delete', entry)
}
</script>

<style scoped>
.explorer-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.entry-tag {
  margin-left: 8px;
}
</style>
