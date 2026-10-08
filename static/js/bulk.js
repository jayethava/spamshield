/**
 * SpamShield: Bulk CSV File Processing & Dynamic Results Management
 */

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileNameDisplay = document.getElementById('fileSelectedName');
  const processBtn = document.getElementById('processBtn');
  const processBtnText = document.getElementById('processBtnText');
  const resetBtn = document.getElementById('resetBulkBtn');
  const uploadForm = document.getElementById('bulkUploadForm');

  const resultsSection = document.getElementById('bulkResultsSection');
  const tbody = document.getElementById('bulkResultsTbody');
  const searchInput = document.getElementById('bulkSearch');
  const verdictFilter = document.getElementById('bulkVerdictFilter');
  const downloadCsvBtn = document.getElementById('downloadResultsCsvBtn');

  let currentResults = [];

  if (!dropzone || !fileInput) return;

  // Drag and drop event listeners
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0 && files[0].name.endsWith('.csv')) {
      fileInput.files = files;
      handleFileSelected(files[0]);
    } else {
      showToast('Please upload a valid .csv file.', 'error');
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  function handleFileSelected(file) {
    fileNameDisplay.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    fileNameDisplay.style.display = 'block';
    processBtn.disabled = false;
    resetBtn.style.display = 'inline-block';
  }

  resetBtn.addEventListener('click', () => {
    fileInput.value = '';
    fileNameDisplay.style.display = 'none';
    processBtn.disabled = true;
    resetBtn.style.display = 'none';
    resultsSection.style.display = 'none';
    currentResults = [];
  });

  // Form submit: upload to /api/bulk-analyze
  uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    processBtn.disabled = true;
    processBtnText.innerHTML = '<span class="spinner"></span> Processing Messages...';

    try {
      const res = await fetch('/api/bulk-analyze', {
        method: 'POST',
        body: formData
      });

      const data = await res.json();

      if (!data.success) {
        showToast(data.error || 'Failed to process CSV.', 'error');
        return;
      }

      currentResults = data.results || [];

      // Update KPI counters
      document.getElementById('bulkTotal').textContent = data.summary.TOTAL || 0;
      document.getElementById('bulkSafe').textContent = data.summary.SAFE || 0;
      document.getElementById('bulkSuspicious').textContent = data.summary.SUSPICIOUS || 0;
      document.getElementById('bulkSpam').textContent = data.summary.SPAM || 0;

      // Reveal results
      renderResultsTable(currentResults);
      resultsSection.style.display = 'block';
      showToast(`Batch completed: ${data.summary.TOTAL} messages scanned.`);

    } catch (err) {
      console.error(err);
      showToast('Error during batch processing.', 'error');
    } finally {
      processBtn.disabled = false;
      processBtnText.textContent = 'Start Bulk Analysis';
    }
  });

  // Render Table
  function renderResultsTable(items) {
    tbody.innerHTML = '';
    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No matching messages found.</td></tr>';
      return;
    }

    items.forEach(item => {
      const tr = document.createElement('tr');
      const scoreColor = item.risk_score >= 65 ? 'var(--spam)' : (item.risk_score >= 35 ? 'var(--suspicious)' : 'var(--safe)');
      const badgeClass = `badge-${item.verdict.toLowerCase()}`;
      const wordsHtml = item.top_words && item.top_words.length > 0 
        ? item.top_words.map(w => `<span class="badge" style="background: var(--spam-bg); color: var(--spam); font-size: 0.72rem; padding: 2px 6px; text-transform: none; margin-right: 4px;">${w}</span>`).join('')
        : '<span style="color: var(--text-dim); font-size: 0.8rem;">None</span>';

      tr.innerHTML = `
        <td style="color: var(--text-muted); font-size: 0.8rem;">${item.id}</td>
        <td>
          ${item.subject ? `<div style="font-weight: 600; font-size: 0.82rem; color: var(--primary);">${item.subject}</div>` : ''}
          <div style="font-size: 0.88rem;">${item.snippet}</div>
        </td>
        <td><span class="badge ${badgeClass}" style="font-size: 0.72rem; padding: 2px 6px;">${item.verdict}</span></td>
        <td><strong style="color: ${scoreColor};">${item.risk_score}%</strong></td>
        <td><span class="badge-category" style="font-size: 0.75rem; padding: 2px 6px;">${item.category}</span></td>
        <td>${wordsHtml}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Filter handlers
  function filterResults() {
    const search = searchInput.value.toLowerCase().trim();
    const verdict = verdictFilter.value.toUpperCase();

    const filtered = currentResults.filter(r => {
      const matchSearch = !search || 
        (r.snippet && r.snippet.toLowerCase().includes(search)) || 
        (r.subject && r.subject.toLowerCase().includes(search)) || 
        (r.category && r.category.toLowerCase().includes(search));
      const matchVerdict = !verdict || r.verdict === verdict;
      return matchSearch && matchVerdict;
    });

    renderResultsTable(filtered);
  }

  if (searchInput) searchInput.addEventListener('input', filterResults);
  if (verdictFilter) verdictFilter.addEventListener('change', filterResults);

  // Download Results CSV
  if (downloadCsvBtn) {
    downloadCsvBtn.addEventListener('click', () => {
      if (!currentResults.length) return;

      const headers = ['ID', 'Subject', 'Snippet', 'Verdict', 'Risk Score (%)', 'Confidence (%)', 'Category', 'Top Words'];
      const rows = currentResults.map(r => [
        r.id,
        `"${(r.subject || '').replace(/"/g, '""')}"`,
        `"${(r.snippet || '').replace(/"/g, '""')}"`,
        r.verdict,
        r.risk_score,
        r.confidence,
        `"${r.category}"`,
        `"${(r.top_words || []).join(', ')}"`
      ]);

      const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', 'SpamShield_Bulk_Predictions.csv');
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      showToast('Predictions CSV downloaded.');
    });
  }
});
