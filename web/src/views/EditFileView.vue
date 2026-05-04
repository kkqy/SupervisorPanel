<template>
  <section class="page">
    <div class="page-header">
      <div>
        <h1 class="page-title">在线编辑文件</h1>
        <p class="page-subtitle">项目：{{ fileData?.project.name || '-' }}；文件：<span class="mono">{{ filePath }}</span></p>
      </div>
      <div class="toolbar">
        <el-button @click="router.push(`/projects/${projectID}`)">返回项目</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </div>
    </div>

    <el-alert title="仅支持常见文本文件，单文件上限 1MB；如果文件已被其他操作修改，保存会被拒绝。" type="info" show-icon :closable="false" />
    <el-card v-loading="loading" shadow="never">
      <el-input v-model="content" class="editor-textarea" type="textarea" resize="vertical" spellcheck="false" />
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { getFileContent, saveFileContent } from '@/api/projects'
import { errorMessage } from '@/api/http'
import type { FileContentResponse } from '@/types/api'

const route = useRoute()
const router = useRouter()
const projectID = Number(route.params.id)
const filePath = typeof route.query.path === 'string' ? route.query.path : ''

const loading = ref(false)
const saving = ref(false)
const fileData = ref<FileContentResponse>()
const content = ref('')
const mtimeNano = ref('0')

onMounted(() => {
  void loadFile()
})

async function loadFile() {
  if (!filePath) {
    ElMessage.error('文件路径缺失')
    await router.push(`/projects/${projectID}`)
    return
  }
  loading.value = true
  try {
    const result = await getFileContent(projectID, filePath)
    fileData.value = result
    content.value = result.content
    mtimeNano.value = result.mtime_nano
  } catch (error) {
    ElMessage.error(errorMessage(error, '读取文件失败'))
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const result = await saveFileContent(projectID, filePath, content.value, mtimeNano.value)
    if (result.mtime_nano) mtimeNano.value = result.mtime_nano
    ElMessage.success(result.message || '保存成功')
  } catch (error) {
    ElMessage.error(errorMessage(error, '保存失败'))
  } finally {
    saving.value = false
  }
}
</script>
