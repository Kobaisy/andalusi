import requests
import json

# API base URL
BASE_URL = "http://localhost:5000/api"

# Global variables to store auth tokens and test data
auth_token = None
admin_token = None
test_redeem_code = None

def test_health_check():
    """Test the health check endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print("Health Check:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_user_registration():
    """Test user registration with valid data"""
    test_data = {
        "email": "test@example.com",
        "password": "TestPassword123"
    }
    
    response = requests.post(
        f"{BASE_URL}/register",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("User Registration Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Store token for later use
    if response.status_code == 201:
        global auth_token
        auth_token = response.json().get('access_token')
        print(f"JWT Token received: {auth_token[:50]}...")
    print("-" * 50)

def test_duplicate_registration():
    """Test registration with duplicate email"""
    test_data = {
        "email": "test@example.com",
        "password": "AnotherPassword123"
    }
    
    response = requests.post(
        f"{BASE_URL}/register",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("Duplicate Registration Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_invalid_email():
    """Test registration with invalid email"""
    test_data = {
        "email": "invalid-email",
        "password": "TestPassword123"
    }
    
    response = requests.post(
        f"{BASE_URL}/register",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("Invalid Email Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_weak_password():
    """Test registration with weak password"""
    test_data = {
        "email": "test2@example.com",
        "password": "123"
    }
    
    response = requests.post(
        f"{BASE_URL}/register",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("Weak Password Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_login():
    """Test user login"""
    test_data = {
        "email": "test@example.com",
        "password": "TestPassword123"
    }
    
    response = requests.post(
        f"{BASE_URL}/login",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("User Login Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Store token for later use if login successful
    if response.status_code == 200:
        global auth_token
        auth_token = response.json().get('access_token')
        print(f"JWT Token received: {auth_token[:50]}...")
    print("-" * 50)

def test_protected_route():
    """Test protected route with JWT token"""
    if not auth_token:
        print("Protected Route Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{BASE_URL}/profile", headers=headers)
    
    print("Protected Route Test (Profile):")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_users():
    """Test getting all users (protected route)"""
    if not auth_token:
        print("Get Users Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{BASE_URL}/users", headers=headers)
    
    print("Get Users Test (Protected):")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_invalid_token():
    """Test protected route with invalid token"""
    headers = {
        "Authorization": "Bearer invalid-token-here",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{BASE_URL}/profile", headers=headers)
    
    print("Invalid Token Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_admin_login():
    """Test admin user login"""
    test_data = {
        "email": "admin@example.com",
        "password": "AdminPassword123"
    }
    
    response = requests.post(
        f"{BASE_URL}/login",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("Admin Login Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Store admin token for later use
    if response.status_code == 200:
        global admin_token
        admin_token = response.json().get('access_token')
        print(f"Admin JWT Token received: {admin_token[:50]}...")
    print("-" * 50)

def test_generate_redeem_codes():
    """Test generating redeem codes (admin only)"""
    if not admin_token:
        print("Generate Codes Test: Skipped (no admin token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }
    
    test_data = {
        "count": 5  # Generate 5 codes for testing
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/admin/generate-codes",
        json=test_data,
        headers=headers
    )
    
    print("Generate Redeem Codes Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_generate_codes_unauthorized():
    """Test generating codes without admin privileges"""
    if not auth_token:
        print("Unauthorized Generate Codes Test: Skipped (no regular token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    test_data = {
        "count": 5
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/admin/generate-codes",
        json=test_data,
        headers=headers
    )
    
    print("Unauthorized Generate Codes Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_redeem_codes():
    """Test getting redeem codes (admin only)"""
    if not admin_token:
        print("Get Redeem Codes Test: Skipped (no admin token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(
        f"{BASE_URL.replace('/api', '')}/admin/codes",
        headers=headers
    )
    
    print("Get Redeem Codes Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Store a test code for redemption testing
    if response.status_code == 200 and response.json().get('codes'):
        global test_redeem_code
        test_redeem_code = response.json()['codes'][0]['code']
        print(f"Test redeem code stored: {test_redeem_code}")
    print("-" * 50)

def test_redeem_code_success():
    """Test successful code redemption"""
    if not auth_token or not test_redeem_code:
        print("Redeem Code Test: Skipped (no token or test code available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Get user ID from token (we'll use 1 as test user)
    test_data = {
        "user_id": 2,  # Assuming test user has ID 2
        "card_code": test_redeem_code
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/redeem",
        json=test_data,
        headers=headers
    )
    
    print("Redeem Code Success Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_redeem_code_duplicate():
    """Test redeeming already used code"""
    if not auth_token or not test_redeem_code:
        print("Duplicate Redeem Code Test: Skipped (no token or test code available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    test_data = {
        "user_id": 2,
        "card_code": test_redeem_code  # Same code as previous test
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/redeem",
        json=test_data,
        headers=headers
    )
    
    print("Duplicate Redeem Code Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_redeem_invalid_code():
    """Test redeeming invalid code"""
    if not auth_token:
        print("Invalid Code Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    test_data = {
        "user_id": 2,
        "card_code": "INVALID-CODE-TEST"
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/redeem",
        json=test_data,
        headers=headers
    )
    
    print("Invalid Code Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_redeem_wrong_user():
    """Test redeeming code for different user (security test)"""
    if not auth_token or not test_redeem_code:
        print("Wrong User Test: Skipped (no token or test code available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    test_data = {
        "user_id": 999,  # Different user ID
        "card_code": test_redeem_code
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/redeem",
        json=test_data,
        headers=headers
    )
    
    print("Wrong User Test (Security):")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription():
    """Test getting user subscription status"""
    if not auth_token:
        print("Get Subscription Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(f"{BASE_URL}/subscription", headers=headers)
    
    print("Get Subscription Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_redeem_unauthorized():
    """Test redeeming without authentication"""
    test_data = {
        "user_id": 2,
        "card_code": "SOME-CODE"
    }
    
    response = requests.post(
        f"{BASE_URL.replace('/api', '')}/redeem",
        json=test_data,
        headers={"Content-Type": "application/json"}
    )
    
    print("Unauthorized Redeem Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription_by_id():
    """Test getting subscription status by user ID"""
    if not auth_token:
        print("Get Subscription by ID Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Test getting own subscription (should work)
    response = requests.get(f"{BASE_URL.replace('/api', '')}/subscription/2", headers=headers)
    
    print("Get Subscription by ID (Own Account) Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription_by_id_unauthorized():
    """Test getting subscription status for different user (should fail for non-admin)"""
    if not auth_token:
        print("Get Subscription by ID (Unauthorized) Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Test getting another user's subscription (should fail for regular users)
    response = requests.get(f"{BASE_URL.replace('/api', '')}/subscription/1", headers=headers)
    
    print("Get Subscription by ID (Unauthorized Access) Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription_by_id_admin():
    """Test getting subscription status by user ID as admin (should work)"""
    if not admin_token:
        print("Get Subscription by ID (Admin) Test: Skipped (no admin token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }
    
    # Test getting any user's subscription as admin (should work)
    response = requests.get(f"{BASE_URL.replace('/api', '')}/subscription/2", headers=headers)
    
    print("Get Subscription by ID (Admin Access) Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription_invalid_user():
    """Test getting subscription for non-existent user"""
    if not auth_token:
        print("Get Subscription (Invalid User) Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Test getting non-existent user's subscription
    response = requests.get(f"{BASE_URL.replace('/api', '')}/subscription/99999", headers=headers)
    
    print("Get Subscription (Invalid User) Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

def test_get_subscription_invalid_format():
    """Test getting subscription with invalid user ID format"""
    if not auth_token:
        print("Get Subscription (Invalid Format) Test: Skipped (no token available)")
        print("-" * 50)
        return
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Test getting subscription with invalid format (should be handled by Flask routing)
    response = requests.get(f"{BASE_URL.replace('/api', '')}/subscription/invalid", headers=headers)
    
    print("Get Subscription (Invalid Format) Test:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print("-" * 50)

if __name__ == "__main__":
    print("Testing User Registration API")
    print("=" * 50)
    
    try:
        test_health_check()
        test_user_registration()
        test_duplicate_registration()
        test_invalid_email()
        test_weak_password()
        test_login()
        test_protected_route()
        test_get_users()
        test_invalid_token()
        test_admin_login()
        test_generate_redeem_codes()
        test_generate_codes_unauthorized()
        test_get_redeem_codes()
        test_redeem_unauthorized()
        test_redeem_code_success()
        test_redeem_code_duplicate()
        test_redeem_invalid_code()
        test_redeem_wrong_user()
        test_get_subscription()
        test_get_subscription_by_id()
        test_get_subscription_by_id_unauthorized()
        test_get_subscription_by_id_admin()
        test_get_subscription_invalid_user()
        test_get_subscription_invalid_format()
        
        print("All tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API. Make sure the Flask app is running on localhost:5000")
    except Exception as e:
        print(f"Error running tests: {e}")
