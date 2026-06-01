const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

export const api = {
  async submitAnalysis(file) {
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      body: formData,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Upload failed')
    }
    return res.json()
  },

  async getJob(jobId) {
    const res = await fetch(`${API_BASE}/api/job/${jobId}`)
    if (!res.ok) throw new Error('Job not found')
    return res.json()
  },

  async getReport(jobId) {
    const res = await fetch(`${API_BASE}/api/report/${jobId}`)
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || 'Report not available')
    }
    return res.json()
  },

  getDownloadUrl(jobId, artifact) {
    return `${API_BASE}/api/download/${jobId}/${artifact}`
  },

  createWebSocket(jobId) {
    const wsBase = API_BASE.replace('http', 'ws')
    return new WebSocket(`${wsBase}/ws/${jobId}`)
  },

  async getHealth() {
    const res = await fetch(`${API_BASE}/api/health`)
    return res.json()
  }
}

export default api
