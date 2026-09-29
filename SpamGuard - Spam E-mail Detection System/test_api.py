import requests

# Test the spam detection API
def test_api():
    base_url = 'http://localhost:5000'

    # Test spam email
    spam_email = "Congratulations! You've won a free iPhone. Click here to claim your prize."
    response = requests.post(f'{base_url}/predict', json={'email_text': spam_email})

    if response.status_code == 200:
        result = response.json()
        print("API /predict test successful")
        print(f"Email: {spam_email}")
        print(f"Prediction: {result.get('prediction', 'N/A')}")
        print(f"Individual predictions: {result.get('individual_predictions', {})}")
    else:
        print(f"API /predict error: {response.status_code}")
        print(response.text)

    # Test ham email
    ham_email = "Hi, how are you doing today? Let's catch up soon."
    response = requests.post(f'{base_url}/predict', json={'email_text': ham_email})

    if response.status_code == 200:
        result = response.json()
        print(f"\nEmail: {ham_email}")
        print(f"Prediction: {result.get('prediction', 'N/A')}")
    else:
        print(f"API /predict error: {response.status_code}")

    # Test unified scan with email + URL
    scan_payload = {
        'email_text': 'URGENT: Verify your account now to avoid suspension.',
        'url': 'http://secure-account-check.top/login?token=abc123',
        'super_scan': True
    }
    response = requests.post(f'{base_url}/scan', json=scan_payload)

    if response.status_code == 200:
        result = response.json()
        print("\nUnified scan test successful")
        print(f"Verdict: {result.get('verdict', 'N/A')}")
        print(f"Risk score: {result.get('risk_score', 'N/A')}")
        print(f"Risk level: {result.get('risk_level', 'N/A')}")

        feedback_payload = {
            'feedback_label': 'scam',
            'email_text': scan_payload['email_text'],
            'url': scan_payload['url'],
            'original_scan': {
                'verdict': result.get('verdict'),
                'risk_level': result.get('risk_level'),
                'risk_score': result.get('risk_score')
            },
            'source': 'api_smoke_test'
        }
        feedback_response = requests.post(f'{base_url}/feedback', json=feedback_payload)
        if feedback_response.status_code == 200:
            print("Feedback endpoint test successful")
        else:
            print(f"API /feedback error: {feedback_response.status_code}")
            print(feedback_response.text)
    else:
        print(f"API /scan error: {response.status_code}")
        print(response.text)

    # Test URL-only scan
    response = requests.post(f'{base_url}/scan', json={'url': 'https://example.com'})
    if response.status_code == 200:
        result = response.json()
        print("\nURL-only scan test successful")
        print(f"Verdict: {result.get('verdict', 'N/A')} | Risk score: {result.get('risk_score', 'N/A')}")
    else:
        print(f"API /scan error: {response.status_code}")

if __name__ == "__main__":
    test_api()