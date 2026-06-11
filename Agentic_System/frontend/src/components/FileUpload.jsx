'use client';

import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle } from 'lucide-react';

export default function FileUpload({ onUploadSuccess, uploadFile, uploadProgress, status }) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [localError, setLocalError] = useState(null);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const validateAndUpload = async (file) => {
    setLocalError(null);

    // Limit to 100MB for static analysis safety
    if (file.size > 100 * 1024 * 1024) {
      setLocalError("File is too large. Maximum supported size is 100MB.");
      return;
    }

    try {
      const analysisId = await uploadFile(file);
      if (onUploadSuccess) {
        onUploadSuccess(analysisId);
      }
    } catch (e) {
      setLocalError(e.message || "Failed to upload file.");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      validateAndUpload(files[0]);
    }
  };

  const handleFileChange = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      validateAndUpload(files[0]);
    }
  };

  const triggerSelect = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const isUploading = status === 'uploading';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={isUploading ? undefined : triggerSelect}
        style={{
          border: isDragOver ? '2px dashed var(--color-primary)' : '2px dashed var(--border-color)',
          background: isDragOver ? 'rgba(0, 212, 255, 0.04)' : 'rgba(255, 255, 255, 0.01)',
          padding: '48px 24px',
          borderRadius: '12px',
          textAlign: 'center',
          cursor: isUploading ? 'not-allowed' : 'pointer',
          transition: 'all 0.2s ease',
          boxShadow: isDragOver ? '0 0 20px rgba(0, 212, 255, 0.1)' : 'none',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '16px'
        }}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          style={{ display: 'none' }}
          disabled={isUploading}
        />
        
        <div style={{
          padding: '16px',
          borderRadius: '50%',
          background: 'rgba(255, 255, 255, 0.03)',
          color: isDragOver ? 'var(--color-primary)' : 'var(--text-muted)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          transition: 'all 0.2s ease',
        }}>
          <UploadCloud size={32} />
        </div>

        {isUploading ? (
          <div style={{ width: '100%', maxWidth: '280px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: '600' }}>Uploading payload...</span>
            <div className="progress-container">
              <div className="progress-bar" style={{ width: `${uploadProgress}%` }} />
            </div>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{uploadProgress}% completed</span>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <span style={{ fontSize: '16px', fontWeight: '600', color: 'var(--text-main)' }}>
              Drag and drop files here, or <span style={{ color: 'var(--color-primary)' }}>browse</span>
            </span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Supports PE (.exe, .dll, .sys), scripts (.ps1, .js, .vbs), and archives (.zip, .iso) up to 100MB
            </span>
          </div>
        )}
      </div>

      {(localError) && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '12px 16px',
          borderRadius: '8px',
          background: 'var(--color-danger-glow)',
          border: '1px solid rgba(255, 51, 102, 0.2)',
          color: 'var(--color-danger)',
          fontSize: '13px'
        }}>
          <AlertCircle size={18} />
          {localError}
        </div>
      )}
    </div>
  );
}
