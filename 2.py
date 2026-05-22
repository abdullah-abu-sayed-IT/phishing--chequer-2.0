#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask Web Application for Phishing Email Detector
Borlekha Charity Foundation - Cybersecurity Tool
"""

from flask import Flask, render_template_string, request, jsonify
from phishing_detector import PhishingDetector
import json

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Detector 🛡️</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .shield-icon {
            font-size: 1.2em;
        }
        
        .content {
            padding: 40px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
            font-size: 1.05em;
        }
        
        input[type="text"],
        textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus,
        textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        textarea {
            resize: vertical;
            min-height: 120px;
        }
        
        .button-group {
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }
        
        button {
            flex: 1;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-analyze {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-analyze:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn-analyze:active {
            transform: translateY(0);
        }
        
        .btn-clear {
            background: #f0f0f0;
            color: #333;
        }
        
        .btn-clear:hover {
            background: #e0e0e0;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
            color: #667eea;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
            margin-top: 40px;
            padding-top: 40px;
            border-top: 2px solid #e0e0e0;
        }
        
        .results.show {
            display: block;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .result-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .risk-badge {
            font-size: 1.5em;
            font-weight: bold;
            padding: 15px 30px;
            border-radius: 10px;
            text-align: center;
        }
        
        .risk-critical {
            background: #ffe0e0;
            color: #c00;
        }
        
        .risk-high {
            background: #fff4e0;
            color: #e67e00;
        }
        
        .risk-medium {
            background: #fffde0;
            color: #b39d00;
        }
        
        .risk-low {
            background: #e0ffe0;
            color: #008000;
        }
        
        .score-bar {
            margin: 20px 0;
        }
        
        .score-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        .progress-bar {
            width: 100%;
            height: 25px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 1s ease-out;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .findings {
            margin-top: 30px;
        }
        
        .finding-item {
            background: #f9f9f9;
            padding: 15px;
            margin-bottom: 12px;
            border-left: 5px solid #ddd;
            border-radius: 5px;
            animation: fadeIn 0.5s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .finding-item.critical {
            border-left-color: #c00;
            background: #ffe0e0;
        }
        
        .finding-item.high {
            border-left-color: #e67e00;
            background: #fff4e0;
        }
        
        .finding-item.medium {
            border-left-color: #b39d00;
            background: #fffde0;
        }
        
        .finding-item.low {
            border-left-color: #008000;
            background: #e0ffe0;
        }
        
        .finding-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .finding-detail {
            font-size: 0.95em;
            color: #666;
        }
        
        .recommendation {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin-top: 25px;
            font-size: 1.1em;
            line-height: 1.6;
        }
        
        .recommendation::before {
            content: "💡 ";
            margin-right: 10px;
        }
        
        .info-box {
            background: #f0f7ff;
            border-left: 5px solid #667eea;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            font-size: 0.95em;
            line-height: 1.6;
        }
        
        .info-box::before {
            content: "ℹ️ ";
            margin-right: 10px;
        }
        
        .footer {
            background: #f9f9f9;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
            color: #666;
        }
        
        .example-btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 10px;
            border: none;
            transition: background 0.3s;
        }
        
        .example-btn:hover {
            background: #764ba2;
        }
        
        @media (max-width: 600px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .content {
                padding: 20px;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            .result-header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <span class="shield-icon">🛡️</span>
                Phishing Email Detector
            </h1>
            <p>Protect yourself from email scams • Borlekha Charity Foundation</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                This tool analyzes email headers and content to detect phishing attempts. 
                Supports both English and Bengali. Always verify suspicious emails independently!
            </div>
            
            <form id="detectorForm">
                <div class="form-group">
                    <label for="sender">Sender Email Address</label>
                    <input type="text" id="sender" name="sender" 
                           placeholder="e.g., security@bankbangladesh.com" required>
                </div>
                
                <div class="form-group">
                    <label for="subject">Email Subject</label>
                    <input type="text" id="subject" name="subject" 
                           placeholder="e.g., URGENT: Verify Your Account" required>
                </div>
                
                <div class="form-group">
                    <label for="body">Email Body (Content)</label>
                    <textarea id="body" name="body" 
                             placeholder="Paste the email content here..." required></textarea>
                </div>
                
                <div class="button-group">
                    <button type="submit" class="btn-analyze">🔍 Analyze Email</button>
                    <button type="reset" class="btn-clear">Clear</button>
                </div>
                
                <div style="margin-top: 20px; text-align: center;">
                    <p style="margin-bottom: 10px; color: #666;">Try demo examples:</p>
                    <button type="button" class="example-btn" onclick="loadExample(1)">
                        Phishing Email Example
                    </button>
                    <button type="button" class="example-btn" onclick="loadExample(2)">
                        Legitimate Email Example
                    </button>
                    <button type="button" class="example-btn" onclick="loadExample(3)">
                        Bengali Phishing Example
                    </button>
                </div>
            </form>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing email...</p>
            </div>
            
            <div class="results" id="results">
                <div class="result-header">
                    <div>
                        <h2>Analysis Results</h2>
                        <p id="analysisTime" style="color: #999; font-size: 0.9em;"></p>
                    </div>
                    <div class="risk-badge" id="riskBadge"></div>
                </div>
                
                <div class="score-bar">
                    <div class="score-label">
                        <span>Risk Score</span>
                        <span id="scoreValue">0/100</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill" style="width: 0%">
                            <span id="scorePercent">0%</span>
                        </div>
                    </div>
                </div>
                
                <div class="findings" id="findingsContainer"></div>
                
                <div class="recommendation" id="recommendation"></div>
            </div>
        </div>
        
        <div class="footer">
            <p>⚠️ Always verify emails independently. When in doubt, contact the official organization directly.</p>
            <p style="margin-top: 10px;">Borlekha Charity Foundation - Cybersecurity Project 2026</p>
        </div>
    </div>
    
    <script>
        const examples = {
            1: {
                sender: "security@bankaisa-update.com",
                subject: "⚠️ URGENT: Verify Your Account Now!",
                body: `Dear User,

Your account has been suspended due to unusual activity.

CLICK HERE NOW to verify your account: http://bit.ly/verify-bank

If you don't verify within 24 hours, your account will be LOCKED FOREVER.

Please confirm your password and credit card number to proceed.

Best regards,
Bank Security Team`
            },
            2: {
                sender: "support@brac.net",
                subject: "Your Monthly Report is Ready",
                body: `Hello Sayeed,

Your monthly charity report for May 2026 is now available.

You can view it at: https://secure.brac.net/reports/user123

If you have any questions, please contact us at support@brac.net

Best regards,
BRAC Support Team`
            },
            3: {
                sender: "security@bankbangladesh-safe.bd",
                subject: "জরুরি: আপনার অ্যাকাউন্ট যাচাই করুন",
                body: `প্রিয় গ্রাহক,

আপনার অ্যাকাউন্ট স্থগিত করা হয়েছে। এখনই নিশ্চিত করুন!

এই লিঙ্কে ক্লিক করুন: http://tinyurl.com/bd-verify

আপনার পাসওয়ার্ড এবং অ্যাকাউন্ট নম্বর নিশ্চিত করুন।

সীমিত সময়ের জন্য!

ধন্যবাদ`
            }
        };
        
        function loadExample(num) {
            const example = examples[num];
            document.getElementById('sender').value = example.sender;
            document.getElementById('subject').value = example.subject;
            document.getElementById('body').value = example.body;
            document.getElementById('results').classList.remove('show');
        }
        
        document.getElementById('detectorForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const sender = document.getElementById('sender').value;
            const subject = document.getElementById('subject').value;
            const body = document.getElementById('body').value;
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').classList.remove('show');
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ sender, subject, body })
                });
                
                const data = await response.json();
                displayResults(data);
            } catch (error) {
                console.error('Error:', error);
                alert('Error analyzing email. Please try again.');
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        });
        
        function displayResults(data) {
            const riskBadge = document.getElementById('riskBadge');
            const risk = data.risk_level.split(' ')[0];
            
            riskBadge.textContent = data.risk_level;
            riskBadge.className = `risk-badge risk-${risk.toLowerCase()}`;
            
            document.getElementById('analysisTime').textContent = data.analysis_timestamp;
            document.getElementById('scoreValue').textContent = `${data.risk_score}/100`;
            
            const progressFill = document.getElementById('progressFill');
            progressFill.style.width = data.risk_score + '%';
            document.getElementById('scorePercent').textContent = data.risk_score + '%';
            
            const findingsContainer = document.getElementById('findingsContainer');
            findingsContainer.innerHTML = '';
            
            if (data.findings.length > 0) {
                const h3 = document.createElement('h3');
                h3.textContent = `🔍 Findings (${data.findings.length} issues)`;
                h3.style.marginBottom = '15px';
                findingsContainer.appendChild(h3);
                
                data.findings.forEach((finding, index) => {
                    const item = document.createElement('div');
                    item.className = `finding-item ${finding.severity.toLowerCase()}`;
                    item.innerHTML = `
                        <div class="finding-title">${index + 1}. ${finding.issue}</div>
                        <div class="finding-detail">${finding.detail}</div>
                    `;
                    findingsContainer.appendChild(item);
                });
            } else {
                const msg = document.createElement('p');
                msg.textContent = '✅ No major issues detected.';
                msg.style.fontSize = '1.1em';
                msg.style.color = '#008000';
                findingsContainer.appendChild(msg);
            }
            
            document.getElementById('recommendation').textContent = data.recommendation;
            document.getElementById('results').classList.add('show');
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    
    detector = PhishingDetector()
    result = detector.analyze_email(
        sender=data.get('sender', ''),
        subject=data.get('subject', ''),
        body=data.get('body', '')
    )
    
    return jsonify(result)

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║   🛡️  Phishing Email Detector Web Application             ║
    ║   Borlekha Charity Foundation                             ║
    ║                                                            ║
    ║   Starting Flask server...                                ║
    ║   Open browser: http://localhost:5000                     ║
    ║                                                            ║
    ║   Press CTRL+C to stop the server                         ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='localhost', port=5000)
