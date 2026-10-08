"""
SpamShield: Explainable SMS & Email Spam/Scam Detector
======================================================
Flask Web Application for College Mini-Project Demo.
Serves interactive UI, REST APIs, Explainable AI insights,
Link Scanner, Analytics Dashboard, and Bulk File Processing.
"""

import os
import io
import csv
import json
from flask import (
    Flask, render_template, request, jsonify,
    send_file, redirect, url_for, flash
)

from detector import detector
import database

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = 'spamshield-college-demo-key-secret-2026'


@app.route('/')
def index():
    """Main Check Message page."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    Analyzes a single message.
    Accepts JSON: { "text": "...", "subject": "..." }
    Returns full analysis payload and stores result in database.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        text = data.get('text', '').strip()
        subject = data.get('subject', '').strip()

        if not text:
            return jsonify({'success': False, 'error': 'Please provide text to analyze.'}), 400

        # Perform analysis
        analysis = detector.analyze(text, subject=subject)
        if not analysis.get('success'):
            return jsonify(analysis), 400

        # Extract flagged word list for database
        flagged_words = [item['word'] for item in analysis.get('top_words', [])]

        # Save to database
        db_id = database.insert_check(
            subject=subject,
            message=text,
            verdict=analysis['verdict'],
            risk_score=analysis['risk_score'],
            confidence=analysis['confidence'],
            category=analysis['category'],
            flagged_words=flagged_words,
            links_count=analysis['links_count'],
            suspicious_links=analysis['suspicious_links_count']
        )
        analysis['check_id'] = db_id

        return jsonify(analysis)

    except Exception as e:
        return jsonify({'success': False, 'error': f"Internal analysis error: {str(e)}"}), 500


@app.route('/history')
def history():
    """History of checked messages with search & filtering."""
    search = request.args.get('search', '').strip()
    verdict = request.args.get('verdict', '').strip()
    category = request.args.get('category', '').strip()

    records = database.get_history(search=search, verdict_filter=verdict, category_filter=category)
    return render_template(
        'history.html',
        records=records,
        search=search,
        verdict=verdict,
        category=category,
        total_count=len(records)
    )


@app.route('/api/history/delete/<int:check_id>', methods=['POST', 'DELETE'])
def api_delete_history(check_id):
    """Deletes a single check record from history."""
    success = database.delete_check(check_id)
    return jsonify({'success': success})


@app.route('/api/history/clear', methods=['POST'])
def api_clear_history():
    """Clears all historical records."""
    count = database.clear_history()
    return jsonify({'success': True, 'deleted_count': count})


@app.route('/history/download')
def history_download():
    """Generates and downloads past checks as a CSV file."""
    rows = database.get_all_rows_for_export()
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'ID', 'Timestamp', 'Subject', 'Message Snippet', 'Verdict',
        'Risk Score (%)', 'Confidence (%)', 'Scam Category',
        'Total Links', 'Suspicious Links'
    ])

    for row in rows:
        writer.writerow([
            row['id'],
            row['timestamp'],
            row['subject'] or '',
            row['snippet'],
            row['verdict'],
            row['risk_score'],
            row['confidence'],
            row['category'],
            row['links_count'],
            row['suspicious_links']
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='SpamShield_History.csv'
    )


@app.route('/dashboard')
def dashboard():
    """Analytics dashboard and ML model evaluation metrics."""
    metrics = detector.metrics
    stats = database.get_analytics_summary()
    return render_template('dashboard.html', metrics=metrics, stats=stats)


@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Returns dynamic data for Chart.js charts."""
    stats = database.get_analytics_summary()
    metrics = detector.metrics
    return jsonify({
        'stats': stats,
        'metrics': metrics
    })


@app.route('/bulk')
def bulk():
    """Bulk message analysis page."""
    return render_template('bulk.html')


@app.route('/api/bulk-analyze', methods=['POST'])
def api_bulk_analyze():
    """
    Accepts CSV upload, extracts messages, runs model and heuristic scanning,
    and returns batch prediction results.
    """
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded.'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Selected file is empty.'}), 400

    try:
        stream = io.StringIO(file.stream.read().decode('utf-8', errors='ignore'))
        reader = csv.reader(stream)
        rows = list(reader)

        if not rows:
            return jsonify({'success': False, 'error': 'The uploaded CSV file is empty.'}), 400

        # Detect columns
        header = [col.strip().lower() for col in rows[0]]
        msg_idx = -1
        subj_idx = -1

        for idx, col in enumerate(header):
            if col in ['message', 'text', 'sms', 'content', 'body']:
                msg_idx = idx
            elif col in ['subject', 'title']:
                subj_idx = idx

        start_row = 1
        if msg_idx == -1:
            # Fallback: assume column 0 is message, or column 1 if column 0 looks like label/subject
            if len(header) >= 2 and header[0] in ['subject', 'type', 'v1', 'label']:
                msg_idx = 1
                subj_idx = 0 if header[0] == 'subject' else -1
            else:
                msg_idx = 0
                start_row = 0

        results = []
        summary = {'SAFE': 0, 'SUSPICIOUS': 0, 'SPAM': 0, 'TOTAL': 0}

        for i, row in enumerate(rows[start_row:], start=1):
            if not row or len(row) <= msg_idx:
                continue
            text = row[msg_idx].strip()
            if not text:
                continue

            subject = row[subj_idx].strip() if (subj_idx != -1 and len(row) > subj_idx) else ""
            analysis = detector.analyze(text, subject=subject)

            if analysis.get('success'):
                summary[analysis['verdict']] = summary.get(analysis['verdict'], 0) + 1
                summary['TOTAL'] += 1

                # Save to database
                database.insert_check(
                    subject=subject,
                    message=text,
                    verdict=analysis['verdict'],
                    risk_score=analysis['risk_score'],
                    confidence=analysis['confidence'],
                    category=analysis['category'],
                    flagged_words=[w['word'] for w in analysis.get('top_words', [])],
                    links_count=analysis['links_count'],
                    suspicious_links=analysis['suspicious_links_count']
                )

                snippet = f"[{subject}] {text}" if subject else text
                if len(snippet) > 75:
                    snippet = snippet[:72] + "..."

                results.append({
                    'id': i,
                    'subject': subject,
                    'snippet': snippet,
                    'verdict': analysis['verdict'],
                    'risk_score': analysis['risk_score'],
                    'confidence': analysis['confidence'],
                    'category': analysis['category'],
                    'links_count': analysis['links_count'],
                    'top_words': [w['word'] for w in analysis.get('top_words', [])[:3]]
                })

        return jsonify({
            'success': True,
            'summary': summary,
            'results': results
        })

    except Exception as e:
        return jsonify({'success': False, 'error': f"Failed to parse CSV file: {str(e)}"}), 500


@app.route('/bulk/sample-csv')
def bulk_sample_csv():
    """Provides downloadable sample CSV for testing the bulk check feature."""
    sample_path = os.path.join(BASE_DIR, 'data', 'sample_bulk.csv')
    if os.path.exists(sample_path):
        return send_file(sample_path, mimetype='text/csv', as_attachment=True, download_name='sample_spam_test.csv')
    return "Sample CSV not found", 404


@app.route('/about')
def about():
    """Educational presentation & viva guide explaining model and explainability."""
    metrics = detector.metrics
    return render_template('about.html', metrics=metrics)


if __name__ == '__main__':
    database.init_db()
    # Run on port 5000 in debug mode for development / demo
    app.run(host='127.0.0.1', port=5000, debug=True)
