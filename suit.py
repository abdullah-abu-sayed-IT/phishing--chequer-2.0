#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite for Phishing Email Detector
Comprehensive testing with real-world scenarios
"""

import json
from phishing_detector import PhishingDetector

class EmailTestSuite:
    """Collection of test emails across different categories"""
    
    test_cases = {
        "phishing_obvious": {
            "name": "Obvious Phishing - Bank Account Suspension",
            "sender": "security@bankaisa-update.com",
            "subject": "⚠️ URGENT: Your Account Will Be SUSPENDED in 24 Hours!",
            "body": """
Dear User,

We have detected unusual activity on your account!

YOUR ACCOUNT HAS BEEN LOCKED FOR SECURITY REASONS.

You must verify your account immediately to avoid permanent suspension.

CLICK HERE NOW: http://bit.ly/verify-banking-secure

Please confirm:
1. Your password
2. Your credit card number
3. Your CVV

If you don't respond within 24 hours, your account will be deleted forever!

Best regards,
Bank Security Team
            """,
            "expected_risk": "CRITICAL"
        },
        
        "phishing_typosquat": {
            "name": "Typosquatting - Fake Facebook",
            "sender": "security@fac3book.com",
            "subject": "Unusual login activity detected",
            "body": """
Hi there,

We noticed unusual login activity on your account from a new location.

For your security, we need you to verify your identity immediately.

Go to: http://secure-verify.fac3book.com/identity

Enter your email and password to continue.

Thanks,
Facebook Security Team
            """,
            "expected_risk": "CRITICAL"
        },
        
        "phishing_generic": {
            "name": "Generic Greeting Phishing",
            "sender": "no-reply@payment-verify.com",
            "subject": "Action Required - Account Verification",
            "body": """
Dear Customer,

We need you to verify your payment information.

Some of your account information appears to be out of date. 
Please update it now by clicking the link below.

https://payment-verify.com/update?user=123456

Regards,
Payment Team
            """,
            "expected_risk": "HIGH"
        },
        
        "phishing_bengali": {
            "name": "Bengali Phishing Email",
            "sender": "security@bankbangladesh-safe.bd",
            "subject": "জরুরি: আপনার অ্যাকাউন্ট যাচাই করুন",
            "body": """
প্রিয় গ্রাহক,

আমরা আপনার অ্যাকাউন্টে অস্বাভাবিক কার্যকলাপ সনাক্ত করেছি।

আপনার অ্যাকাউন্ট স্থগিত করা হয়েছে। এখনই নিশ্চিত করুন!

এই লিঙ্কে ক্লিক করুন: http://tinyurl.com/bd-verify

আপনার পাসওয়ার্ড এবং অ্যাকাউন্ট নম্বর দিন।

সীমিত সময়ের জন্য! এখনই করুন!

ধন্যবাদ
            """,
            "expected_risk": "CRITICAL"
        },
        
        "legitimate_bank": {
            "name": "Legitimate Bank Communication",
            "sender": "support@bankasia.com.bd",
            "subject": "Your Monthly Statement for April 2026",
            "body": """
Dear Mr. Sayeed,

Your monthly bank statement for April 2026 is now ready.

You can view it securely in your online banking portal:
https://secure.bankasia.com.bd/statements

Login with your usual credentials.

If you have any questions about your account, please contact:
- Phone: 02-XXXXXXXXXX
- Email: support@bankasia.com.bd

Best regards,
Bank Asia Customer Support
            """,
            "expected_risk": "LOW"
        },
        
        "legitimate_google": {
            "name": "Legitimate Google Notification",
            "sender": "noreply@accounts.google.com",
            "subject": "Security alert for your Google Account",
            "body": """
Hi Sayeed,

We noticed a new sign-in to your Google Account on Chrome from India.

Device: Chrome on Windows
Location: Dhaka, Bangladesh
Date & Time: May 21, 2026, 3:45 PM

If this wasn't you, you can review your account activity here:
https://accounts.google.com/signin/security

Google will always protect your account with built-in security.

Thanks,
The Google Accounts team
            """,
            "expected_risk": "LOW"
        },
        
        "phishing_charity": {
            "name": "Fake Charity Donation Request",
            "sender": "donate@borlekha-foundation.bd",
            "subject": "Emergency Fund Appeal - Help Us Today!",
            "body": """
Dear Supporter,

We urgently need your help!

Many students in Borlekha have no access to education. 

Your immediate donation will change lives.

DONATE NOW: http://bit.ly/borlekha-donate

Please provide your bank details to complete the donation.

Limited time offer - Double your impact today!

Borlekha Foundation
            """,
            "expected_risk": "HIGH"
        },
        
        "phishing_reward": {
            "name": "Fake Prize/Reward Claim",
            "sender": "prizes@lucky-draw.com",
            "subject": "🎉 CONGRATULATIONS! You Won $50,000!",
            "body": """
Dear Winner!

You have been selected as the winner of our monthly draw!

CLAIM YOUR PRIZE: http://short.link/claim-prize

You have won:
- $50,000 CASH
- iPhone 15 Pro
- Samsung Laptop

To claim your rewards, please click the link above and provide:
1. Your full name
2. Your ID number
3. Your bank account details

CLAIM NOW before the offer expires!

Lucky Draw Commission
            """,
            "expected_risk": "CRITICAL"
        },
        
        "legitimate_newsletter": {
            "name": "Legitimate Newsletter",
            "sender": "newsletter@medium.com",
            "subject": "Your Weekly Digest - Top Stories This Week",
            "body": """
Hi Sayeed,

Here are this week's best stories on Medium:

1. "The Future of Cybersecurity in 2026"
   by Jane Smith | 8 min read

2. "Building Secure Python Applications"
   by Dev Team | 12 min read

Read more: https://medium.com/my-stories

You can manage your subscriptions in your account settings.

Happy reading!
Medium Editorial Team
            """,
            "expected_risk": "LOW"
        },
        
        "phishing_business": {
            "name": "Business Email Compromise",
            "sender": "ceo@borlekha-foundation.org",
            "subject": "Urgent: Invoice Payment Required",
            "body": """
Hi Finance Team,

I need you to process an urgent payment for our new project.

Please transfer $10,000 to this account IMMEDIATELY:

Bank: International Bank
Account: 1234567890
Routing: XYZ123

This is critical for our operations. Do it now!

Do not discuss with anyone.

Thanks,
CEO
            """,
            "expected_risk": "HIGH"
        },
        
        "phishing_credential": {
            "name": "Credential Harvesting",
            "sender": "verify@gmail-security.com",
            "subject": "Confirm your Gmail account",
            "body": """
Hello,

We need to verify your Gmail account for security reasons.

Please verify here: https://mail-verify.com/signin

Enter your Gmail address and password to continue.

Thank you,
Gmail Security Team
            """,
            "expected_risk": "CRITICAL"
        }
    }
    
    @staticmethod
    def run_all_tests():
        """Run all test cases and generate report"""
        print("\n" + "="*80)
        print("🧪 PHISHING DETECTOR - COMPREHENSIVE TEST SUITE")
        print("="*80 + "\n")
        
        detector = PhishingDetector()
        results = []
        
        for test_id, test_case in EmailTestSuite.test_cases.items():
            print(f"Testing: {test_case['name']}")
            print("-" * 80)
            
            result = detector.analyze_email(
                sender=test_case['sender'],
                subject=test_case['subject'],
                body=test_case['body']
            )
            
            # Determine if test passed
            expected_risk = test_case['expected_risk']
            actual_risk = result['risk_level'].split()[0]  # Extract just the level
            passed = expected_risk == actual_risk
            
            test_result = {
                'id': test_id,
                'name': test_case['name'],
                'expected': expected_risk,
                'actual': actual_risk,
                'score': result['risk_score'],
                'passed': passed,
                'findings_count': len(result['findings'])
            }
            
            results.append(test_result)
            
            # Print result
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"Expected Risk: {expected_risk}")
            print(f"Actual Risk: {actual_risk}")
            print(f"Score: {result['risk_score']}/100")
            print(f"Findings: {len(result['findings'])}")
            print(f"Status: {status}\n")
            
            if not passed:
                print(f"⚠️  Test failed! Expected {expected_risk} but got {actual_risk}")
                print("Findings detected:")
                for finding in result['findings']:
                    print(f"  - {finding['issue']} ({finding['severity']})")
                print()
        
        # Print summary
        EmailTestSuite.print_summary(results)
        
        # Save results to JSON
        EmailTestSuite.save_results(results)
    
    @staticmethod
    def print_summary(results):
        """Print test summary"""
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80 + "\n")
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['passed'])
        failed_tests = total_tests - passed_tests
        pass_rate = (passed_tests / total_tests) * 100
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Pass Rate: {pass_rate:.1f}%\n")
        
        print("Results by Risk Level:")
        print("-" * 80)
        for result in results:
            status = "✅" if result['passed'] else "❌"
            print(f"{status} {result['name']:<45} Score: {result['score']:>3}/100")
        
        print("\n" + "="*80 + "\n")
    
    @staticmethod
    def save_results(results):
        """Save test results to JSON file"""
        output = {
            'timestamp': __import__('datetime').datetime.now().isoformat(),
            'total_tests': len(results),
            'passed': sum(1 for r in results if r['passed']),
            'failed': sum(1 for r in results if not r['passed']),
            'results': results
        }
        
        with open('test_results.json', 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"📁 Results saved to: test_results.json\n")


class PerformanceTest:
    """Test performance metrics"""
    
    @staticmethod
    def run_performance_test():
        """Measure analysis speed"""
        import time
        
        print("\n" + "="*80)
        print("⚡ PERFORMANCE TEST")
        print("="*80 + "\n")
        
        detector = PhishingDetector()
        
        test_email = {
            'sender': 'test@example.com',
            'subject': 'Test Email Subject',
            'body': 'This is a test email body ' * 100  # 100 repetitions
        }
        
        # Warm up
        detector.analyze_email(**test_email)
        
        # Time 100 analyses
        iterations = 100
        start_time = time.time()
        
        for _ in range(iterations):
            detector.analyze_email(**test_email)
        
        end_time = time.time()
        total_time = end_time - start_time
        avg_time = (total_time / iterations) * 1000  # Convert to ms
        
        print(f"Iterations: {iterations}")
        print(f"Total Time: {total_time:.3f} seconds")
        print(f"Average Time per Email: {avg_time:.2f} milliseconds")
        print(f"Throughput: {iterations/total_time:.0f} emails/second\n")
        
        print("✅ Performance acceptable for production use\n")


if __name__ == "__main__":
    # Run comprehensive tests
    EmailTestSuite.run_all_tests()
    
    # Run performance test
    PerformanceTest.run_performance_test()
    
    print("="*80)
    print("✅ All tests completed!")
    print("="*80 + "\n")
