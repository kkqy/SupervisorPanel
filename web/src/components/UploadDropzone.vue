<template>
  <div class="upload-dropzone" :class="{ active: dragging, busy: uploading }" @dragenter.prevent="dragging = true" @dragover.prevent="dragging = true" @dragleave.prevent="dragging = false" @drop.prevent="handleDrop">
    <div class="drop-title">拖拽文件或文件夹到这里上传</div>
    <div class="drop-subtitle">支持多文件；浏览器支持目录拖拽时会保留目录结构。</div>
    <div class="drop-actions">
      <el-button type="primary" :loading="uploading" @click="pickFiles">选择文件</el-button>
      <input ref="fileInput" hidden type="file" multiple @change="handlePicked" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'

const props = defineProps<{
  uploading: boolean
}>()

const emit = defineEmits<{
  upload: [files: Array<{ file: File; path: string }>]
}>()

const dragging = ref(false)
const fileInput = ref<HTMLInputElement>()

function pickFiles() {
  if (props.uploading) return
  if (fileInput.value) {
    fileInput.value.value = ''
    fileInput.value.click()
  }
}

async function handleDrop(event: DragEvent) {
  dragging.value = false
  if (props.uploading) return
  if (!event.dataTransfer) {
    ElMessage.error('未检测到拖拽数据')
    return
  }
  const files = await parseDroppedFiles(event.dataTransfer)
  emit('upload', files)
}

function handlePicked() {
  const selected = Array.from(fileInput.value?.files || [])
  emit(
    'upload',
    selected.map((file) => ({ file, path: normalizeDroppedPath(file.webkitRelativePath || file.name) })),
  )
}

function normalizeDroppedPath(raw: string) {
  return String(raw || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/^\.\//, '')
}

function pathDepth(relPath: string) {
  if (!relPath) return 0
  return relPath.split('/').filter(Boolean).length
}

function pickBetterPath(currentPath: string, nextPath: string) {
  const current = normalizeDroppedPath(currentPath)
  const next = normalizeDroppedPath(nextPath)
  if (!next) return current
  if (!current) return next
  const currentDepth = pathDepth(current)
  const nextDepth = pathDepth(next)
  if (nextDepth > currentDepth) return next
  if (nextDepth < currentDepth) return current
  return next.length > current.length ? next : current
}

function walkEntry(entry: FileSystemEntry, prefix: string): Promise<Array<{ file: File; path: string }>> {
  return new Promise((resolve) => {
    if (entry.isFile) {
      ;(entry as FileSystemFileEntry).file(
        (file) => {
          const byPrefix = normalizeDroppedPath(`${prefix ? `${prefix}/` : ''}${file.name}`)
          const byFullPath = normalizeDroppedPath(entry.fullPath)
          const byWebkitPath = normalizeDroppedPath(file.webkitRelativePath || '')
          resolve([{ file, path: pickBetterPath(pickBetterPath(byPrefix, byFullPath), byWebkitPath) }])
        },
        () => resolve([]),
      )
      return
    }
    if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      const allEntries: FileSystemEntry[] = []
      const readAll = () => {
        reader.readEntries(
          async (entries) => {
            if (!entries.length) {
              const allFiles: Array<{ file: File; path: string }> = []
              for (const child of allEntries) {
                allFiles.push(...(await walkEntry(child, `${prefix ? `${prefix}/` : ''}${entry.name}`)))
              }
              resolve(allFiles)
              return
            }
            allEntries.push(...entries)
            readAll()
          },
          () => resolve([]),
        )
      }
      readAll()
      return
    }
    resolve([])
  })
}

async function parseDroppedFiles(dataTransfer: DataTransfer) {
  const plainFiles = Array.from(dataTransfer.files || [])
  const items = Array.from(dataTransfer.items || [])
  const hasDirectory = items.some((item) => {
    const entry = item.kind === 'file' && item.webkitGetAsEntry ? item.webkitGetAsEntry() : null
    return !!entry?.isDirectory
  })
  if (!hasDirectory) {
    return plainFiles.map((file) => ({ file, path: normalizeDroppedPath(file.webkitRelativePath || file.name) }))
  }

  const resultsByIdentity = new Map<string, { file: File; path: string }>()
  const addFile = (file: File, relPath: string) => {
    const cleanPath = normalizeDroppedPath(relPath || file.webkitRelativePath || file.name || '')
    if (!cleanPath) return
    const identity = `${file.name}|${file.size}|${file.lastModified || 0}`
    const existed = resultsByIdentity.get(identity)
    if (!existed) {
      resultsByIdentity.set(identity, { file, path: cleanPath })
      return
    }
    existed.path = pickBetterPath(existed.path, cleanPath)
  }

  for (const item of items) {
    if (item.kind !== 'file') continue
    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null
    if (entry) {
      const files = await walkEntry(entry, '')
      files.forEach((file) => addFile(file.file, file.path))
      continue
    }
    const file = item.getAsFile()
    if (file) addFile(file, file.name)
  }

  const merged = Array.from(resultsByIdentity.values())
  if (merged.length) return merged
  return plainFiles.map((file) => ({ file, path: normalizeDroppedPath(file.webkitRelativePath || file.name) }))
}
</script>

<style scoped>
.upload-dropzone {
  display: grid;
  gap: 10px;
  place-items: center;
  min-height: 190px;
  padding: 24px;
  border: 1px dashed var(--el-border-color);
  border-radius: 10px;
  background: var(--el-fill-color-lighter);
  text-align: center;
  transition: border-color 0.18s, background 0.18s;
}

.upload-dropzone.active {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}

.upload-dropzone.busy {
  opacity: 0.72;
  pointer-events: none;
}

.drop-title {
  font-size: 16px;
  font-weight: 650;
}

.drop-subtitle {
  color: var(--el-text-color-secondary);
}
</style>
