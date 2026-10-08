"""
Automated Test Suite for SpamShield
===================================
Tests all routes, verifies 5 sample messages (2 safe, 3 scam),
checks Explainable AI outputs, link scanner, database persistence,
and bulk CSV analysis.
"""

import os
import json
import io
from app import app
import database

def run_tests():
    print("=" * 60)
    print("Running SpamShield Automated Verification Suite")
    print("=" * 60)

    client = app.test_client()

    # Test 1: Route availability
    routes = ['/', '/history', '/dashboard', '/bulk', '/about', '/api/dashboard-data']
    for r in routes:
        res = client.get(r)
        assert res.status_code == 200, f"Route {r} returned {res.status_code}"
        print(f"[PASS] Route GET {r} (HTTP 200)")

    # Test 2: Analyze 5 Sample Messages (3 Scam, 2 Safe)
    samples = [
        # Scam 1: SBI KYC Phishing
        {
            'type': 'SCAM',
            'category': 'Fake KYC / Banking',
            'subject': 'Urgent: YONO Suspended',
            'text': 'Dear SBI Customer, your YONO account has been suspended due to pending PAN KYC. Click http://sbi-kyc-update.xyz/verify immediately to avoid permanent deactivation.'
        },
        # Scam 2: KBC WhatsApp Lottery
        {
            'type': 'SCAM',
            'category': 'Lottery / Reward Scam',
            'subject': 'Congratulations Winner',
            'text': 'Congratulations! Your mobile number has won Rs 25,00,000 in KBC Kaun Banega Crorepati WhatsApp Lucky Draw. Call Rana Pratap Singh on +919876543210 to claim prize.'
        },
        # Scam 3: Electricity Disconnection Alert
        {
            'type': 'SCAM',
            'category': 'Electricity Bill Disconnection',
            'subject': 'Power Cut Notice',
            'text': 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please call electricity officer at 9876543210 immediately.'
        },
        # Safe 1: Personal Family Message
        {
            'type': 'SAFE',
            'category': 'Safe / Legitimate',
            'subject': 'Dinner Update',
            'text': 'Hi Mom, I will reach home by 7 PM today. Please keep dinner ready.'
        },
        # Safe 2: Food Delivery Notification
        {
            'type': 'SAFE',
            'category': 'Safe / Legitimate',
            'subject': 'Swiggy Delivery',
            'text': 'Swiggy: Your order from Biryani Blues is on the way! Delivery partner Manoj is arriving in 12 mins. Track live in your Swiggy app.'
        }
    ]

    print("\n--- Testing 5 Target Sample Messages ---")
    for i, s in enumerate(samples, 1):
        res = client.post('/api/analyze', json={'text': s['text'], 'subject': s['subject']})
        assert res.status_code == 200, f"Analyze failed for sample {i}: {res.data}"
        data = res.get_json()

        verdict = data['verdict']
        score = data['risk_score']
        category = data['category']
        top_words = [w['word'] for w in data['top_words']]
        links_count = len(data['links'])

        print(f"\nSample {i} [{s['type']} - {s['category']}]:")
        print(f"  Snippet: {s['text'][:65]}...")
        print(f"  Verdict: {verdict} | Risk Score: {score}% | Category: {category}")
        print(f"  Flagged Words: {top_words[:4]}")
        print(f"  Links Detected: {links_count}")

        if s['type'] == 'SCAM':
            assert verdict in ['SPAM', 'SUSPICIOUS'], f"Expected SCAM, got {verdict}"
            assert score >= 60, f"Expected risk >= 60, got {score}"
        else:
            assert verdict == 'SAFE', f"Expected SAFE, got {verdict}"
            assert score < 35, f"Expected risk < 35, got {score}"

        print(f"  [PASS] Sample {i} classified correctly as expected!")

    # Test 3: History Database Storage & Retrieval
    records = database.get_history()
    assert len(records) >= 5, f"Expected at least 5 history records, found {len(records)}"
    print(f"\n[PASS] Database successfully recorded {len(records)} history records.")

    # Test 4: CSV History Download
    dl_res = client.get('/history/download')
    assert dl_res.status_code == 200
    assert 'text/csv' in dl_res.content_type
    assert b'Risk Score' in dl_res.data
    print(f"[PASS] /history/download generated valid CSV ({len(dl_res.data)} bytes).")

    # Test 5: Bulk CSV Upload Analysis
    sample_csv_path = os.path.join(os.path.dirname(__file__), 'data', 'sample_bulk.csv')
    with open(sample_csv_path, 'rb') as f:
        bulk_res = client.post(
            '/api/bulk-analyze',
            data={'file': (io.BytesIO(f.read()), 'sample_bulk.csv')},
            content_type='multipart/form-data'
        )
    assert bulk_res.status_code == 200, f"Bulk upload failed: {bulk_res.data}"
    bulk_data = bulk_res.get_json()
    assert bulk_data['success'] is True
    print(f"[PASS] /api/bulk-analyze processed {bulk_data['summary']['TOTAL']} messages successfully.")
    print(f"       Summary: {bulk_data['summary']}")

    # Test 6: Dashboard Aggregation
    dash_res = client.get('/api/dashboard-data')
    dash_data = dash_res.get_json()
    assert dash_data['stats']['total_checks'] > 0
    print(f"[PASS] Dashboard API returned live stats for {dash_data['stats']['total_checks']} total messages.")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == '__main__':
    run_tests()
