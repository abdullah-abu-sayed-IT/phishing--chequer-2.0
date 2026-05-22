#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing Email Detector - Borlekha Charity Foundation
Bengali & English Support
Author: Cybersecurity Project
"""

import re
import json
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import hashlib

class PhishingDetector:
    """
    Detects phishing emails using multiple analysis techniques
    """
    
    def __init__(self):
        # Suspicious keywords (Bangla + English)
        self.urgent_keywords = {
            'en': ['verify', 'confirm', 'urgent', 'immediate', 'click here', 
                   'act now', 'validate', 'update account', 'unusual activity',
                   'suspended', 'locked', 'claim reward', 'limited time'],
            'bn': ['যাচাই', 'নিশ্চিত করুন', 'জরুরি', 'এখনই', 'ক্লিক করুন',
                   'অ্যাকাউন্ট আপডেট', 'অস্বাভাবিক কার্যকলাপ', 'স্থগিত',
                   'পুরস্কার', 'সীমিত সময়']
        }
        
        # Common phishing domains (example patterns)
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 'goo.gl',
            'ow.ly', 'tiny.cc', 'u.nu'
        ]
        
        # Legitimate bank/service patterns
        self.legitimate_domains = {
            'brac': ['brac.net', 'bracu.ac.bd'],
            'bank': ['bangladesh.com', 'bankasia.com.bd'],
            'google': ['google.com', 'accounts.google.com'],
            'facebook': ['facebook.com', 'meta.com'],
            'mail': ['gmail.com', 'outlook.com', 'yahoo.com']
        }
        
        self.risk_score = 0
        self.findings = []
    
    def analyze_email(self, sender: str, subject: str, body: str, 
                     links: List[str] = None) -> Dict:
        """
        Complete email analysis with risk scoring
        """
        self.risk_score = 0
        self.findings = []
        
        # Run all checks
        self._check_sender_spoofing(sender)
        self._check_urgent_language(subject + " " + body)
        self._check_suspicious_links(links or self._extract_links(body))
        self._check_spelling_grammar(body)
        self._check_urgency_threat(body)
        self._check_generic_greeting(body)
        self._check_suspicious_requests(body)
        
        return self._generate_report(sender, subject, body)
    
    def _check_sender_spoofing(self, sender: str) -> None:
        """Check if sender looks suspicious"""
        # Check for unusual characters or mismatches
        if sender.count('@') != 1:
            self.risk_score += 15
            self.findings.append({
                'issue': 'Invalid sender format',
                'severity': 'HIGH',
                'detail': 'Email address has unusual format'
            })
            return
        
        local_part, domain = sender.split('@')
        
        # Check if domain looks like banking/official but is spoofed
        if any(keyword in local_part.lower() for keyword in 
               ['bank', 'admin', 'support', 'security']):
            if not self._is_legitimate_domain(domain):
                self.risk_score += 20
                self.findings.append({
                    'issue': 'Spoofed sender',
                    'severity': 'CRITICAL',
                    'detail': f'Sender claims to be official but domain "{domain}" is suspicious'
                })
        
        # Check for typosquatting (common misspellings)
        typosquat_patterns = [
            (r'g00gle', 'google'),
            (r'fac3book', 'facebook'),
            (r'y4h00', 'yahoo'),
            (r'gmai1', 'gmail')
        ]
        
        for pattern, real in typosquat_patterns:
            if re.search(pattern, sender, re.IGNORECASE):
                self.risk_score += 25
                self.findings.append({
                    'issue': 'Typosquatting detected',
                    'severity': 'CRITICAL',
                    'detail': f'Sender mimics "{real}" with spelling variation'
                })
    
    def _check_urgent_language(self, text: str) -> None:
        """Detect urgent/threatening language"""
        text_lower = text.lower()
        
        # Check English urgent keywords
        en_matches = sum(1 for keyword in self.urgent_keywords['en'] 
                        if keyword in text_lower)
        
        # Check Bangla urgent keywords
        bn_matches = sum(1 for keyword in self.urgent_keywords['bn'] 
                        if keyword in text)
        
        total_matches = en_matches + bn_matches
        
        if total_matches >= 3:
            self.risk_score += 20
            self.findings.append({
                'issue': 'Excessive urgent language',
                'severity': 'HIGH',
                'detail': f'Found {total_matches} urgent keywords (common phishing tactic)'
            })
        elif total_matches >= 1:
            self.risk_score += 10
            self.findings.append({
                'issue': 'Some urgent language detected',
                'severity': 'MEDIUM',
                'detail': f'Found {total_matches} urgent keyword(s)'
            })
    
    def _check_suspicious_links(self, links: List[str]) -> None:
        """Analyze links in email"""
        if not links:
            return
        
        for link in links:
            try:
                parsed = urlparse(link)
                domain = parsed.netloc.lower()
                
                # Check for URL shorteners
                if any(short_domain in domain for short_domain in self.suspicious_domains):
                    self.risk_score += 15
                    self.findings.append({
                        'issue': 'URL shortener detected',
                        'severity': 'HIGH',
                        'detail': f'Link uses {domain} - hides true destination'
                    })
                
                # Check for IP addresses instead of domain
                if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                    self.risk_score += 20
                    self.findings.append({
                        'issue': 'IP address used instead of domain',
                        'severity': 'CRITICAL',
                        'detail': f'Suspicious link: {link}'
                    })
                
                # Check for mismatched domain
                if 'bank' in link.lower() and 'bank' not in domain:
                    self.risk_score += 15
                    self.findings.append({
                        'issue': 'Domain mismatch',
                        'severity': 'HIGH',
                        'detail': f'Link mentions banking but domain is "{domain}"'
                    })
                
            except Exception as e:
                self.findings.append({
                    'issue': 'Invalid link format',
                    'severity': 'MEDIUM',
                    'detail': str(e)
                })
    
    def _check_spelling_grammar(self, text: str) -> None:
        """Check for poor grammar/spelling (common in phishing)"""
        # Common misspellings in phishing emails
        misspellings = [
            (r'\bmust\b', r'\bmust\b'),  # excessive repetition
            (r'[a-z]{6,}\s[a-z]{6,}\s[a-z]{6,}\s[a-z]{6,}', 'long repetitive words')
        ]
        
        # Check for all caps (aggressive)
        all_caps_words = len(re.findall(r'\b[A-Z]{4,}\b', text))
        if all_caps_words > 5:
            self.risk_score += 10
            self.findings.append({
                'issue': 'Excessive capitalization',
                'severity': 'MEDIUM',
                'detail': 'Multiple words in ALL CAPS (aggressive tone)'
            })
        
        # Check for poor English (grammatical errors)
        grammar_issues = len(re.findall(r'\s{2,}|[!?]{2,}', text))
        if grammar_issues > 3:
            self.risk_score += 8
            self.findings.append({
                'issue': 'Poor grammar detected',
                'severity': 'LOW',
                'detail': 'Multiple spacing/punctuation issues'
            })
    
    def _check_urgency_threat(self, text: str) -> None:
        """Check for threat/urgency combinations"""
        threat_phrases = [
            r'your\s+account\s+will\s+be\s+(closed|suspended|locked)',
            r'verify\s+your\s+(password|account|identity)',
            r'click.*now|act.*immediately|limited\s+time',
            r'confirm\s+your\s+(details|information)',
            r'আপনার\s+অ্যাকাউন্ট',
            r'নিশ্চিত\s+করুন'
        ]
        
        matches = sum(1 for pattern in threat_phrases 
                     if re.search(pattern, text, re.IGNORECASE))
        
        if matches >= 2:
            self.risk_score += 15
            self.findings.append({
                'issue': 'Threat + Urgency combination',
                'severity': 'HIGH',
                'detail': 'Email combines threats with urgency (classic phishing)'
            })
    
    def _check_generic_greeting(self, text: str) -> None:
        """Check for generic greetings (not personalized)"""
        generic_greetings = [
            r'dear\s+user',
            r'dear\s+customer',
            r'dear\s+sir',
            r'hello\s+there',
            r'গ্রাহক\s+মহোদয়'
        ]
        
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in generic_greetings):
            self.risk_score += 8
            self.findings.append({
                'issue': 'Generic greeting',
                'severity': 'LOW',
                'detail': 'Email not personalized (legitimate emails usually use your name)'
            })
    
    def _check_suspicious_requests(self, text: str) -> None:
        """Check for suspicious data requests"""
        sensitive_requests = [
            (r'password', 'Password request'),
            (r'credit\s+card|card\s+number', 'Credit card info'),
            (r'social\s+security|ssn', 'SSN/Personal ID'),
            (r'bank\s+account', 'Bank account details'),
            (r'পাসওয়ার্ড', 'পাসওয়ার্ড অনুরোধ'),
            (r'ব্যাংক\s+অ্যাকাউন্ট', 'ব্যাংক অ্যাকাউন্ট বিস্তারিত')
        ]
        
        for pattern, description in sensitive_requests:
            if re.search(pattern, text, re.IGNORECASE):
                self.risk_score += 20
                self.findings.append({
                    'issue': 'Sensitive data request',
                    'severity': 'CRITICAL',
                    'detail': f'Email requests: {description}'
                })
    
    def _extract_links(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s\)]*'
        return re.findall(url_pattern, text)
    
    def _is_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is known legitimate"""
        domain_lower = domain.lower()
        for service, domains in self.legitimate_domains.items():
            if any(legit in domain_lower for legit in domains):
                return True
        return False
    
    def _generate_report(self, sender: str, subject: str, 
                        body: str) -> Dict:
        """Generate final risk report"""
        
        # Determine risk level
        if self.risk_score >= 60:
            risk_level = 'CRITICAL 🔴'
            recommendation = 'DELETE THIS EMAIL IMMEDIATELY. Do not click any links.'
        elif self.risk_score >= 40:
            risk_level = 'HIGH 🟠'
            recommendation = 'Very suspicious. Verify sender independently before responding.'
        elif self.risk_score >= 20:
            risk_level = 'MEDIUM 🟡'
            recommendation = 'Be cautious. Do not click suspicious links.'
        else:
            risk_level = 'LOW 🟢'
            recommendation = 'Appears legitimate, but always be vigilant.'
        
        return {
            'risk_level': risk_level,
            'risk_score': min(self.risk_score, 100),
            'findings': self.findings,
            'recommendation': recommendation,
            'sender': sender,
            'subject': subject,
            'analysis_timestamp': self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def print_report(self, report: Dict) -> None:
        """Pretty print the report"""
        print("\n" + "="*70)
        print("🛡️  PHISHING EMAIL ANALYSIS REPORT")
        print("="*70)
        print(f"\n📧 Sender: {report['sender']}")
        print(f"📌 Subject: {report['subject']}")
        print(f"⏰ Analysis Time: {report['analysis_timestamp']}")
        print(f"\n⚠️  RISK LEVEL: {report['risk_level']}")
        print(f"📊 Risk Score: {report['risk_score']}/100")
        
        if report['findings']:
            print(f"\n🔍 FINDINGS ({len(report['findings'])} issues):")
            print("-" * 70)
            for i, finding in enumerate(report['findings'], 1):
                severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 
                                'MEDIUM': '🟡', 'LOW': '🟢'}
                emoji = severity_emoji.get(finding['severity'], '❓')
                print(f"{i}. {emoji} [{finding['severity']}] {finding['issue']}")
                print(f"   → {finding['detail']}\n")
        else:
            print("\n✅ No major issues detected.")
        
        print(f"\n💡 RECOMMENDATION:")
        print(f"{report['recommendation']}")
        print("\n" + "="*70 + "\n")


# Example usage
if __name__ == "__main__":
    # Test Case 1: Obvious Phishing
    detector = PhishingDetector()
    
    print("\n" + "🧪 TEST CASE 1: OBVIOUS PHISHING EMAIL")
    result1 = detector.analyze_email(
        sender="security@bankaisa-update.com",
        subject="⚠️ URGENT: Verify Your Account Now!",
        body="""
        Dear User,
        
        Your account has been suspended due to unusual activity.
        
        CLICK HERE NOW to verify your account: http://bit.ly/verify-bank
        
        If you don't verify within 24 hours, your account will be LOCKED FOREVER.
        
        Please confirm your password and credit card number to proceed.
        
        Best regards,
        Bank Security Team
        """
    )
    detector.print_report(result1)
    
    # Test Case 2: Legitimate Email
    detector2 = PhishingDetector()
    
    print("\n" + "🧪 TEST CASE 2: LEGITIMATE EMAIL")
    result2 = detector2.analyze_email(
        sender="support@brac.net",
        subject="Your Monthly Report is Ready",
        body="""
        Hello Sayeed,
        
        Your monthly charity report for May 2026 is now available.
        
        You can view it at: https://secure.brac.net/reports/user123
        
        If you have any questions, please contact us at support@brac.net
        
        Best regards,
        BRAC Support Team
        """
    )
    detector2.print_report(result2)
    
    # Test Case 3: Bengali Phishing
    detector3 = PhishingDetector()
    
    print("\n" + "🧪 TEST CASE 3: BENGALI PHISHING EMAIL")
    result3 = detector3.analyze_email(
        sender="security@bankbangladesh-safe.bd",
        subject="জরুরি: আপনার অ্যাকাউন্ট যাচাই করুন",
        body="""
        প্রিয় গ্রাহক,
        
        আপনার অ্যাকাউন্ট স্থগিত করা হয়েছে। এখনই নিশ্চিত করুন!
        
        এই লিঙ্কে ক্লিক করুন: http://tinyurl.com/bd-verify
        
        আপনার পাসওয়ার্ড এবং অ্যাকাউন্ট নম্বর নিশ্চিত করুন।
        
        সীমিত সময়ের জন্য!
        
        ধন্যবাদ
        """
    )
    detector3.print_report(result3)
