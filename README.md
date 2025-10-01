# Enterprise User Registration API with Advanced Security & Scalability

A production-ready Flask-based REST API for user registration, authentication with JWT tokens, admin-only redeem code generation, and secure code redemption with subscription management. Built to handle enterprise-scale requirements with advanced security measures.

## Features

- User registration with email and password
- User login with JWT token generation
- JWT token-based authentication
- Protected routes with token verification
- **Admin-only redeem code generation**
- **Secure, unique, non-guessable codes**
- **Database storage with usage tracking**
- **Code redemption with race condition prevention**
- **Subscription management and extension**
- **Atomic database transactions for security**
- **Enterprise-scale performance optimization**
- **Advanced rate limiting and security**
- **Cryptographically secure code generation**
- **Optimized database indexing**
- **Comprehensive security monitoring**
- Email format validation
- Password strength validation
- Duplicate email prevention
- Secure password hashing
- SQLite database storage (PostgreSQL recommended for production)
- Health check endpoint
- Error handling and validation

## Requirements

- Python 3.7+
- Flask
- Flask-SQLAlchemy
- Werkzeug
- python-dotenv
- PyJWT
- Flask-Limiter (for rate limiting)
- Redis (for distributed rate limiting)
- python-memcached (optional, for caching)

## Installation

1. Clone or download the project files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables (optional):
   ```bash
   # Create a .env file with:
   SECRET_KEY=your-secret-key-here
   JWT_SECRET_KEY=your-jwt-secret-key-here
   DATABASE_URL=sqlite:///users.db
   ADMIN_EMAIL=admin@yourdomain.com
   ADMIN_PASSWORD=YourSecureAdminPassword123
   REDIS_URL=redis://localhost:6379/0
   ```

## Usage

1. Start the Flask application:
   ```bash
   python app.py
   ```

2. The API will be available at `http://localhost:5000`

## API Endpoints

### POST /api/register
Register a new user.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "YourPassword123"
}
```

**Response (Success - 201):**
```json
{
    "message": "User registered successfully",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "created_at": "2023-12-01T10:30:00.000000"
    },
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

**Response (Error - 400/409):**
```json
{
    "error": "Error message"
}
```

### POST /api/login
Login an existing user.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "YourPassword123"
}
```

**Response (Success - 200):**
```json
{
    "message": "Login successful",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "created_at": "2023-12-01T10:30:00.000000"
    },
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### GET /api/profile
Get current user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response (Success - 200):**
```json
{
    "user": {
        "id": 1,
        "email": "user@example.com",
        "created_at": "2023-12-01T10:30:00.000000"
    }
}
```

### GET /api/users
Get all registered users (requires authentication).

**Headers:**
```
Authorization: Bearer <your-jwt-token>
```

**Response (200):**
```json
{
    "users": [
        {
            "id": 1,
            "email": "user@example.com",
            "created_at": "2023-12-01T10:30:00.000000"
        }
    ]
}
```

### POST /admin/generate-codes
Generate redeem codes (Admin only).

**Headers:**
```
Authorization: Bearer <admin-jwt-token>
```

**Request Body:**
```json
{
    "count": 1000
}
```

**Response (Success - 201):**
```json
{
    "message": "Successfully generated 1000 redeem codes",
    "count": 1000,
    "codes": [
        "A1B2C3D4E5F6-G7H8-I9J0K1L2",
        "M3N4O5P6Q7R8-S9T0-U1V2W3X4",
        ...
    ]
}
```

### GET /admin/codes
Get all redeem codes with pagination (Admin only).

**Headers:**
```
Authorization: Bearer <admin-jwt-token>
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Items per page (default: 50)
- `used` (optional): Filter by usage status (`true`/`false`)

**Response (Success - 200):**
```json
{
    "codes": [
        {
            "id": 1,
            "code": "A1B2C3D4E5F6-G7H8-I9J0K1L2",
            "is_used": false,
            "created_at": "2023-12-01T10:30:00.000000",
            "expires_at": null
        }
    ],
    "total": 1000,
    "pages": 20,
    "current_page": 1,
    "per_page": 50
}
```

### POST /redeem
Redeem a code to extend user subscription (authenticated users only).

**Headers:**
```
Authorization: Bearer <user-jwt-token>
```

**Request Body:**
```json
{
    "user_id": 123,
    "card_code": "A1B2C3D4E5F6-G7H8-I9J0K1L2"
}
```

**Response (Success - 200):**
```json
{
    "message": "Code redeemed successfully",
    "subscription_extended": true,
    "new_subscription_expiry": "2024-01-01T10:30:00.000000",
    "redeemed_at": "2023-12-01T10:30:00.000000"
}
```

**Response (Error - 409):**
```json
{
    "error": "Code has already been used"
}
```

**Response (Error - 404):**
```json
{
    "error": "Invalid redeem code"
}
```

### GET /api/subscription
Get current user's subscription status (authenticated users only).

**Headers:**
```
Authorization: Bearer <user-jwt-token>
```

**Response (Success - 200):**
```json
{
    "user_id": 123,
    "email": "user@example.com",
    "is_subscribed": true,
    "subscription_expires_at": "2024-01-01T10:30:00.000000"
}
```

### GET /subscription/:user_id
Get subscription status for any user by user ID (authenticated users only).

**Headers:**
```
Authorization: Bearer <user-jwt-token>
```

**Parameters:**
- `user_id` (path): The ID of the user to check

**Security Rules:**
- Users can only check their own subscription status
- Admins can check any user's subscription status

**Response (Success - 200):**
```json
{
    "user_id": 123,
    "email": "user@example.com",
    "is_subscribed": true,
    "subscription_status": "active",
    "subscription_expires_at": "2024-01-01T10:30:00.000000",
    "days_remaining": 15,
    "created_at": "2023-12-01T10:30:00.000000"
}
```

**Response (Error - 403):**
```json
{
    "error": "Access denied. You can only check your own subscription status"
}
```

**Response (Error - 404):**
```json
{
    "error": "User not found"
}
```

**Subscription Status Values:**
- `active`: Subscription is currently valid
- `expired`: Subscription has expired
- `inactive`: User has never had a subscription

### GET /api/health
Health check endpoint.

**Response (200):**
```json
{
    "status": "healthy",
    "message": "User Registration API is running"
}
```

## Password Requirements

- Minimum 8 characters
- At least one letter
- At least one number

## JWT Token

- Tokens expire after 1 hour
- Include token in Authorization header: `Bearer <token>`
- Tokens contain user ID and email
- Protected routes require valid token

## Admin Features

- **Default Admin Account**: `admin@example.com` / `AdminPassword123`
- **Redeem Code Generation**: Create secure, unique codes at scale
- **Code Security**: UUID4-based with additional entropy
- **Usage Tracking**: Track which codes are used and by whom
- **Admin-only Access**: All admin endpoints require admin privileges

## Code Redemption Features

- **Race Condition Prevention**: Atomic database transactions with row-level locking
- **One-Time Use**: Codes can only be redeemed once
- **Subscription Extension**: Each code extends subscription by 1 month
- **Security Validation**: Users can only redeem codes for their own account
- **Input Sanitization**: Code format validation and sanitization
- **Transaction Safety**: Full rollback on any failure

## Subscription Management Features

- **User-Specific Access**: Users can check their own subscription status
- **Admin Override**: Admins can check any user's subscription status
- **Detailed Status Information**: Active, expired, or inactive status
- **Days Remaining Calculation**: Shows remaining subscription days
- **Comprehensive Data**: Includes user details and subscription history

## Email Validation

- Valid email format required
- Duplicate emails are not allowed

## Testing

Run the test script to verify the API functionality:

```bash
python test_api.py
```

Make sure the Flask app is running before executing the tests.

## Database

The application uses SQLite by default. The database file (`users.db`) will be created automatically when you first run the application.

## Security Features

### Advanced Security Measures
- **Cryptographically secure code generation** with multiple entropy sources
- **Rate limiting** to prevent brute-force attacks (10 redemptions/minute)
- **Hash-based database lookups** for optimal performance and security
- **Comprehensive audit logging** for security monitoring
- **Row-level database locking** to prevent race conditions

### Code Security
- **2^256 possible combinations** - virtually impossible to guess
- **SHA-256 hashing** for additional entropy and validation
- **Microsecond timestamp precision** for uniqueness
- **Checksum validation** to prevent tampering
- **No sequential patterns** or predictable sequences

### Production Security
- Passwords are hashed using Werkzeug's security functions
- JWT tokens are signed with a secret key
- Never expose SECRET_KEY or JWT_SECRET_KEY in production
- Use environment variables for sensitive configuration
- In production, use PostgreSQL or MySQL with proper indexing
- JWT tokens expire after 1 hour for security
- Redis-backed distributed rate limiting

## Error Handling

The API returns appropriate HTTP status codes:
- 200: Success
- 201: Created
- 400: Bad Request (validation errors)
- 401: Unauthorized (invalid credentials or missing token)
- 403: Forbidden (admin privileges required)
- 409: Conflict (duplicate email)
- 500: Internal Server Error

## Example Usage with JWT

**1. Register a new user:**
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "MyPassword123"}'
```

**2. Login (or use token from registration):**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "MyPassword123"}'
```

**3. Access protected route:**
```bash
curl -X GET http://localhost:5000/api/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

**4. Login as admin:**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "AdminPassword123"}'
```

**5. Generate redeem codes (admin only):**
```bash
curl -X POST http://localhost:5000/admin/generate-codes \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"count": 1000}'
```

**6. View generated codes (admin only):**
```bash
curl -X GET http://localhost:5000/admin/codes \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN_HERE"
```

**7. Redeem a code:**
```bash
curl -X POST http://localhost:5000/redeem \
  -H "Authorization: Bearer USER_JWT_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 123, "card_code": "A1B2C3D4E5F6-G7H8-I9J0K1L2"}'
```

**8. Check subscription status:**
```bash
curl -X GET http://localhost:5000/api/subscription \
  -H "Authorization: Bearer USER_JWT_TOKEN_HERE"
```

**9. Check specific user's subscription (own account):**
```bash
curl -X GET http://localhost:5000/subscription/123 \
  -H "Authorization: Bearer USER_JWT_TOKEN_HERE"
```

**10. Check any user's subscription (admin only):**
```bash
curl -X GET http://localhost:5000/subscription/456 \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN_HERE"
```

## Scalability & Performance

This system is designed to handle enterprise-scale requirements:

- **100k code generations per day** - Optimized batch processing
- **10M users** - Efficient database indexing and partitioning
- **1k redemption requests per second** - Hash-based lookups and atomic transactions

### Performance Optimizations

- **Hash-based lookups**: O(1) vs O(n) for code validation
- **Composite database indexes**: Optimized for high-frequency queries
- **Batch operations**: Efficient processing of large code batches
- **Row-level locking**: Minimal lock time for concurrent operations
- **Rate limiting**: Distributed Redis-backed protection

### Monitoring & Logging

- **Security audit logs**: Track all redemption attempts and failures
- **Performance metrics**: Response times and processing statistics
- **Rate limiting logs**: Monitor and prevent abuse
- **Database performance**: Query optimization and index usage

For detailed scalability information, see [SCALABILITY.md](SCALABILITY.md).

For database schema details, see [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

## Testing

Run the comprehensive test suite:

```bash
python test_api.py
```

The test suite includes:
- User registration and authentication
- Admin code generation and management
- Code redemption with security validation
- Rate limiting and error handling
- Subscription management
- Cross-user security validation
