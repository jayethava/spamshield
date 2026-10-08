/**
 * SpamShield: Dashboard Charts Initialization
 * Visualizes Verdict Breakdown, Scam Category Distribution,
 * and Scan Activity Timeline via Chart.js
 */

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch('/api/dashboard-data');
    const data = await res.json();
    const stats = data.stats || {};

    const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDarkMode ? '#94a3b8' : '#64748b';
    const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.06)' : 'rgba(0, 0, 0, 0.06)';

    // Global Chart.js defaults
    Chart.defaults.color = textColor;
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

    // 1. Verdict Breakdown Doughnut Chart
    const verdictCtx = document.getElementById('verdictChart');
    if (verdictCtx) {
      const vCounts = stats.verdict_counts || { SAFE: 0, SUSPICIOUS: 0, SPAM: 0 };
      const total = (vCounts.SAFE || 0) + (vCounts.SUSPICIOUS || 0) + (vCounts.SPAM || 0);

      // Default visual demo values if database has 0 scans yet
      const safeVal = total > 0 ? vCounts.SAFE : 1;
      const suspVal = total > 0 ? vCounts.SUSPICIOUS : 0;
      const spamVal = total > 0 ? vCounts.SPAM : 0;

      new Chart(verdictCtx, {
        type: 'doughnut',
        data: {
          labels: ['Safe', 'Suspicious', 'Spam'],
          datasets: [{
            data: [safeVal, suspVal, spamVal],
            backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
            borderWidth: 0,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { padding: 15, boxWidth: 12 }
            },
            tooltip: {
              callbacks: {
                label: (ctx) => ` ${ctx.label}: ${total > 0 ? ctx.raw : (ctx.raw + ' (Demo)')}`
              }
            }
          },
          cutout: '72%'
        }
      });
    }

    // 2. Scam Category Horizontal Bar Chart
    const catCtx = document.getElementById('categoryChart');
    if (catCtx) {
      let catData = stats.category_counts || {};
      let labels = Object.keys(catData);
      let values = Object.values(catData);

      if (labels.length === 0) {
        // Fallback default representative categories for presentation
        labels = ['Fake KYC / Banking', 'Lottery / Reward', 'OTP Fraud', 'Electricity Bill', 'Fake Job Offer', 'Safe / Legit'];
        values = [12, 8, 7, 5, 4, 15];
      }

      new Chart(catCtx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Total Scans',
            data: values,
            backgroundColor: [
              '#ef4444', '#f97316', '#eab308', '#8b5cf6', '#ec4899', '#10b981', '#3b82f6'
            ],
            borderRadius: 6
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: gridColor },
              ticks: { precision: 0 }
            },
            y: {
              grid: { display: false }
            }
          }
        }
      });
    }

    // 3. Scan Activity Timeline Chart
    const timeCtx = document.getElementById('timelineChart');
    if (timeCtx) {
      let timeline = stats.timeline || [];
      let labels = timeline.map(t => t.date);
      let values = timeline.map(t => t.count);

      if (labels.length === 0) {
        const today = new Date().toISOString().slice(0, 10);
        labels = [today];
        values = [stats.total_checks || 1];
      }

      new Chart(timeCtx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Messages Analyzed',
            data: values,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.12)',
            fill: true,
            tension: 0.35,
            pointRadius: 4,
            pointBackgroundColor: '#3b82f6'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { color: gridColor }
            },
            y: {
              beginAtZero: true,
              grid: { color: gridColor },
              ticks: { precision: 0 }
            }
          }
        }
      });
    }

  } catch (err) {
    console.error('Failed to load dashboard telemetry:', err);
  }
});
