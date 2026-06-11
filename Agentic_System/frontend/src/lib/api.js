const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let errDetail = 'Request failed';
    try {
      const err = await response.json();
      errDetail = err.detail || err.message || errDetail;
    } catch (_) {}
    throw new Error(errDetail);
  }

  return response.json();
}

export const api = {
  // File upload and analyses
  uploadFile: async (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    
    return new Promise((resolve, reject) => {
      xhr.open('POST', `${BASE_URL}/api/analysis/upload`, true);
      
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && onProgress) {
          const progress = Math.round((event.loaded / event.total) * 100);
          onProgress(progress);
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch (e) {
            reject(new Error('Failed to parse upload response'));
          }
        } else {
          reject(new Error(xhr.responseText || 'Upload failed'));
        }
      };

      xhr.onerror = () => reject(new Error('Network error during upload'));
      xhr.send(formData);
    });
  },

  getAnalysis: (id) => request(`/api/analysis/${id}`),
  
  getAnalysisReport: (id) => request(`/api/analysis/${id}/report`),
  
  getAnalysisJson: (id) => request(`/api/analysis/${id}/json`),
  
  getAnalysisHistory: () => request('/api/analysis/history'),
  
  deleteAnalysis: (id) => request(`/api/analysis/${id}`, { method: 'DELETE' }),

  // Settings
  getSettings: () => request('/api/settings'),
  
  updateSettings: (settings) => request('/api/settings', {
    method: 'PUT',
    body: JSON.stringify(settings),
  }),
  
  testConnection: (provider, credentials) => request('/api/settings/test-connection', {
    method: 'POST',
    body: JSON.stringify({ provider, ...credentials }),
  }),
  
  getProviders: () => request('/api/settings/providers'),
  
  getRecentReports: () => request('/api/reports/recent'),
  
  getReportDownloadUrl: (id) => `${BASE_URL}/api/reports/${id}/download`,
  
  getWsUrl: (id) => {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = BASE_URL.replace(/^https?:\/\//, '');
    return `${wsProto}//${host}/ws/${id}`;
  },
  
  getGlobalWsUrl: () => {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = BASE_URL.replace(/^https?:\/\//, '');
    return `${wsProto}//${host}/ws/global`;
  }
};
