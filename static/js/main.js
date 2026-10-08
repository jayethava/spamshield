/**
 * SpamShield: Main Client-side Script
 * Handles Theme Toggling, Quick Samples, AJAX Analysis,
 * Circular Gauge Animation, and Dynamic DOM Updates.
 */

// Sample messages catalog
const SAMPLE_MESSAGES = {
  kyc: {
    subject: "Urgent Notice: Account Suspended",
    text: "Dear SBI Customer, your YONO account has been suspended due to pending PAN KYC. Click http://sbi-kyc-update.xyz/verify immediately to avoid permanent deactivation."
  },
  lottery: {
    subject: "KBC Lucky Draw Selection",
    text: "Congratulations! Your mobile number has won Rs 25,00,000 in KBC Kaun Banega Crorepati WhatsApp Lucky Draw. Call Rana Pratap Singh on +919876543210 to claim prize."
  },
  electricity: {
    subject: "Power Cut Alert",
    text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please call electricity officer at 9876543210 immediately."
  },
  job: {
    subject: "Part-Time WFH Job Offer",
    text: "Part time job offer: Work from home daily 1-2 hours and earn Rs 3000 to Rs 8000 daily by liking YouTube videos and Google reviews. Telegram @hr_priya_recruiter"
  },
  otp: {
    subject: "Card Transaction Alert",
    text: "Your OTP for transaction of Rs 49,999 is 849201. If not done by you, immediately share this OTP with customer care officer on +919123456789 to cancel."
  },
  safe_personal: {
    subject: "",
    text: "Hey Rahul, are we meeting for the project discussion in library at 4 PM today? Let me know."
  },
  safe_delivery: {
    subject: "Order Picked Up",
    text: "Swiggy: Your order from Biryani Blues is on the way! Delivery partner Manoj is arriving in 12 mins. Track live in your Swiggy app."
  }
};

// --- Theme Management ---
function initTheme() {
  const currentTheme = localStorage.getItem('spamshield_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  updateThemeButton(currentTheme);

  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const active = document.documentElement.getAttribute('data-theme');
      const next = active === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('spamshield_theme', next);
      updateThemeButton(next);
    });
  }
}

function updateThemeButton(theme) {
  const icon = document.getElementById('themeIcon');
  const text = document.getElementById('themeText');
  if (icon && text) {
    if (theme === 'dark') {
      icon.textContent = '☀️';
      text.textContent = 'Light';
    } else {
      icon.textContent = '🌙';
      text.textContent = 'Dark';
    }
  }
}

// --- Toast Notifications ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// --- Textarea Counters ---
function initCounters() {
  const textarea = document.getElementById('messageInput');
  const counter = document.getElementById('charCounter');
  if (!textarea || !counter) return;

  function update() {
    const val = textarea.value.trim();
    const chars = textarea.value.length;
    const words = val ? val.split(/\s+/).length : 0;
    counter.textContent = `${chars} characters • ${words} words`;
  }

  textarea.addEventListener('input', update);
  update();
}

// --- Sample Chips Loader ---
function initSampleChips() {
  const chips = document.querySelectorAll('.sample-chip');
  const subjectInput = document.getElementById('subjectInput');
  const messageInput = document.getElementById('messageInput');

  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const key = chip.getAttribute('data-sample');
      if (SAMPLE_MESSAGES[key]) {
        if (subjectInput) subjectInput.value = SAMPLE_MESSAGES[key].subject || '';
        if (messageInput) {
          messageInput.value = SAMPLE_MESSAGES[key].text;
          messageInput.dispatchEvent(new Event('input'));
          messageInput.focus();
        }
        showToast(`Loaded "${chip.textContent.trim()}" sample.`);
      }
    });
  });

  const clearBtn = document.getElementById('clearBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (subjectInput) subjectInput.value = '';
      if (messageInput) {
        messageInput.value = '';
        messageInput.dispatchEvent(new Event('input'));
      }
    });
  }
}

// --- Circular Gauge Visualizer ---
function updateRiskGauge(score, verdict) {
  const fill = document.getElementById('gaugeFill');
  const scoreNum = document.getElementById('riskScoreNumber');
  if (!fill || !scoreNum) return;

  // Circumference of r=40 is 2 * PI * 40 ≈ 251.2
  const circumference = 251.2;
  const offset = circumference - (score / 100) * circumference;

  let color = '#10b981'; // Safe green
  if (score >= 65) {
    color = '#ef4444'; // Spam red
  } else if (score >= 35) {
    color = '#f59e0b'; // Suspicious amber
  }

  fill.style.stroke = color;
  fill.style.strokeDashoffset = offset;
  scoreNum.textContent = `${score}%`;
  scoreNum.style.color = color;
}

// --- Main Form Submission & Results Rendering ---
function initAnalysisForm() {
  const form = document.getElementById('analyzeForm');
  if (!form) return;

  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('btnText');
  const emptyState = document.getElementById('emptyState');
  const resultContent = document.getElementById('resultContent');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const subject = document.getElementById('subjectInput').value.trim();
    const text = document.getElementById('messageInput').value.trim();

    if (!text) {
      showToast('Please enter message text to analyze.', 'error');
      return;
    }

    // Set loading state
    btn.disabled = true;
    const originalText = btnText.textContent;
    btnText.innerHTML = '<span class="spinner"></span> Analyzing...';

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, subject })
      });

      const data = await response.json();

      if (!data.success) {
        showToast(data.error || 'Analysis failed.', 'error');
        return;
      }

      // Hide empty state, reveal result
      emptyState.style.display = 'none';
      resultContent.style.display = 'block';

      // 1. Verdict & Category Badges
      const verdictBadge = document.getElementById('verdictBadge');
      verdictBadge.textContent = data.verdict;
      verdictBadge.className = `badge badge-${data.verdict.toLowerCase()}`;

      const catBadge = document.getElementById('categoryBadge');
      catBadge.textContent = data.category;

      const modelNameText = document.getElementById('modelNameText');
      if (modelNameText) modelNameText.textContent = data.model_name || 'Multinomial Naive Bayes';

      // 2. Risk Score & Confidence
      updateRiskGauge(data.risk_score, data.verdict);
      document.getElementById('confidenceValue').textContent = `${data.confidence}%`;

      const threatSummary = document.getElementById('threatSummary');
      if (data.verdict === 'SPAM') {
        threatSummary.textContent = 'High probability fraudulent threat detected.';
        threatSummary.style.color = 'var(--spam)';
      } else if (data.verdict === 'SUSPICIOUS') {
        threatSummary.textContent = 'Caution advised. Borderline spam indicators found.';
        threatSummary.style.color = 'var(--suspicious)';
      } else {
        threatSummary.textContent = 'Safe message. No critical threats discovered.';
        threatSummary.style.color = 'var(--safe)';
      }

      // 3. Explainable AI Highlights
      const highlightBox = document.getElementById('highlightedTextBox');
      highlightBox.innerHTML = data.highlighted_html || text;

      // 4. Top 5 Why Flagged Words
      const whyList = document.getElementById('whyFlaggedList');
      whyList.innerHTML = '';
      if (data.top_words && data.top_words.length > 0) {
        data.top_words.forEach(item => {
          const div = document.createElement('div');
          div.className = 'why-flagged-item';
          div.innerHTML = `
            <span class="why-word">${item.word}</span>
            <span class="why-reason">${item.explanation}</span>
            <span class="why-weight">+${item.weight} (${item.impact})</span>
          `;
          whyList.appendChild(div);
        });
      } else {
        whyList.innerHTML = '<div style="font-size: 0.85rem; color: var(--text-muted); padding: 0.4rem;">No elevated spam keywords identified.</div>';
      }

      // 5. Link Scanner
      const linksCountBadge = document.getElementById('linksCountBadge');
      const linksList = document.getElementById('linksList');
      linksList.innerHTML = '';

      if (data.links && data.links.length > 0) {
        linksCountBadge.textContent = `${data.links.length} URL(s) inspected (${data.suspicious_links_count} flagged)`;
        data.links.forEach(l => {
          const card = document.createElement('div');
          card.className = `link-card ${l.risk_level.toLowerCase()}`;
          const flagsHtml = l.flags.map(f => `<li>${f}</li>`).join('');
          card.innerHTML = `
            <div class="link-header">
              <span class="link-url">${l.url}</span>
              <span class="badge badge-${l.risk_level === 'Clean' ? 'safe' : (l.risk_level === 'Suspicious' ? 'suspicious' : 'spam')}" style="font-size: 0.72rem; padding: 2px 7px;">
                ${l.risk_level}
              </span>
            </div>
            <ul class="link-flags">${flagsHtml}</ul>
          `;
          linksList.appendChild(card);
        });
      } else {
        linksCountBadge.textContent = '0 links detected in text';
        linksList.innerHTML = '<div style="font-size: 0.85rem; color: var(--text-dim); padding: 0.4rem;">No hyperlinks embedded in this message.</div>';
      }

      // 6. Safety Tips
      const tipsList = document.getElementById('tipsList');
      tipsList.innerHTML = '';
      if (data.safety_tips && data.safety_tips.length > 0) {
        data.safety_tips.forEach(t => {
          const li = document.createElement('li');
          li.textContent = t;
          tipsList.appendChild(li);
        });
      }

      showToast(`Analysis complete: ${data.verdict} (${data.risk_score}%)`);

    } catch (err) {
      console.error(err);
      showToast('Network error during analysis.', 'error');
    } finally {
      btn.disabled = false;
      btnText.textContent = originalText;
    }
  });
}

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initCounters();
  initSampleChips();
  initAnalysisForm();
});
