# Database Schema Documentation

## Overview

This document describes the normalized database schema implemented according to the suggested specification. The schema follows best practices for scalability, performance, and maintainability.

## Tables

### 1. users
**Purpose**: Store user account information

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY | Auto-incrementing user ID |
| email | VARCHAR(120) | UNIQUE, NOT NULL, INDEX | User's email address |
| password_hash | VARCHAR(255) | NOT NULL | Hashed password |
| is_admin | BOOLEAN | NOT NULL, DEFAULT FALSE | Admin privileges flag |
| created_at | DATETIME | DEFAULT NOW() | Account creation timestamp |

**Indexes:**
- Primary key on `id`
- Unique index on `email`

### 2. redeem_cards
**Purpose**: Store redeem codes with usage tracking

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY | Auto-incrementing card ID |
| code | VARCHAR(50) | UNIQUE, NOT NULL, INDEX | The redeem code |
| is_used | BOOLEAN | NOT NULL, DEFAULT FALSE | Usage status |
| expires_at | DATETIME | NULLABLE | Code expiration date (optional) |
| redeemed_by | INTEGER | NULLABLE, FOREIGN KEY | User ID who redeemed the code |
| created_at | DATETIME | DEFAULT NOW() | Code creation timestamp |

**Indexes:**
- Primary key on `id`
- **Unique index on `code`** (as specified)
- Index on `redeemed_by` for user redemption history
- Index on `is_used` for filtering unused codes

**Foreign Keys:**
- `redeemed_by` → `users.id`

### 3. subscriptions
**Purpose**: Track user subscription periods

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY | Auto-incrementing subscription ID |
| user_id | INTEGER | NOT NULL, INDEX, FOREIGN KEY | User ID |
| expires_at | DATETIME | NOT NULL, INDEX | Subscription expiration date |
| created_at | DATETIME | DEFAULT NOW() | Subscription creation timestamp |

**Indexes:**
- Primary key on `id`
- **Index on `user_id`** (as specified)
- Index on `expires_at` for subscription queries
- Composite index on `user_id, expires_at` for active subscription lookups

**Foreign Keys:**
- `user_id` → `users.id`

## Schema Benefits

### 1. Normalization
- **Separated concerns**: Users, codes, and subscriptions are in separate tables
- **Reduced redundancy**: No duplicate subscription data per user
- **Flexibility**: Easy to add new features without schema changes

### 2. Performance Optimizations
- **Efficient lookups**: Indexed columns for common queries
- **Composite indexes**: Optimized for complex queries
- **Foreign key constraints**: Data integrity with referential integrity

### 3. Scalability
- **Partitioning ready**: Tables can be partitioned by user_id or date ranges
- **Read replicas friendly**: Clean separation of read/write operations
- **Horizontal scaling**: Schema supports sharding strategies

## Query Patterns

### Common Queries and Their Optimization

#### 1. User Authentication
```sql
SELECT id, email, password_hash, is_admin 
FROM users 
WHERE email = ?;
```
**Optimization**: Index on `email` ensures O(log n) lookup

#### 2. Code Redemption
```sql
SELECT id, code, is_used, expires_at 
FROM redeem_cards 
WHERE code = ? AND is_used = FALSE;
```
**Optimization**: Unique index on `code` + index on `is_used` for fast filtering

#### 3. Active Subscription Check
```sql
SELECT expires_at 
FROM subscriptions 
WHERE user_id = ? AND expires_at > NOW();
```
**Optimization**: Composite index on `user_id, expires_at` for optimal performance

#### 4. User Redemption History
```sql
SELECT code, created_at 
FROM redeem_cards 
WHERE redeemed_by = ? 
ORDER BY created_at DESC;
```
**Optimization**: Index on `redeemed_by` + ordering by `created_at`

#### 5. Admin Code Management
```sql
SELECT code, is_used, expires_at, redeemed_by 
FROM redeem_cards 
WHERE is_used = ? 
ORDER BY created_at DESC 
LIMIT ? OFFSET ?;
```
**Optimization**: Index on `is_used` + ordering by `created_at`

## Migration Strategy

### From Previous Schema
If migrating from the previous schema:

1. **Create new tables** with the normalized structure
2. **Migrate user data** from existing users table
3. **Migrate redeem codes** to new redeem_cards table
4. **Create subscriptions** from existing subscription_expires_at data
5. **Update application code** to use new schema
6. **Drop old columns** after verification

### Migration Script Example
```sql
-- Create subscriptions from existing user data
INSERT INTO subscriptions (user_id, expires_at, created_at)
SELECT id, subscription_expires_at, created_at
FROM users 
WHERE subscription_expires_at IS NOT NULL;

-- Migrate redeem codes
INSERT INTO redeem_cards (code, is_used, redeemed_by, created_at)
SELECT code, is_used, used_by, created_at
FROM redeem_codes;
```

## Performance Considerations

### 1. Index Usage
- All specified indexes are implemented
- Composite indexes optimize multi-column queries
- Foreign key indexes support JOIN operations

### 2. Query Optimization
- **Hash-based lookups**: For code validation (when implemented)
- **Batch operations**: For large code generation
- **Pagination**: Built-in support for large result sets

### 3. Scaling Strategies
- **Read replicas**: Separate read/write workloads
- **Partitioning**: By user_id ranges or date ranges
- **Caching**: Frequently accessed data can be cached

## Security Considerations

### 1. Data Integrity
- **Foreign key constraints**: Prevent orphaned records
- **Unique constraints**: Prevent duplicate codes
- **NOT NULL constraints**: Ensure data completeness

### 2. Access Control
- **Database-level security**: Proper user permissions
- **Application-level security**: JWT-based authentication
- **Admin-only operations**: Protected admin endpoints

### 3. Audit Trail
- **Creation timestamps**: Track when records are created
- **Redemption tracking**: Who redeemed what code when
- **Subscription history**: Complete subscription lifecycle

## Monitoring and Maintenance

### 1. Performance Monitoring
- **Query execution times**: Monitor slow queries
- **Index usage**: Ensure indexes are being utilized
- **Connection pooling**: Monitor database connections

### 2. Data Maintenance
- **Expired code cleanup**: Regular cleanup of expired codes
- **Subscription management**: Handle expired subscriptions
- **User data retention**: Comply with data retention policies

### 3. Backup Strategy
- **Regular backups**: Automated database backups
- **Point-in-time recovery**: Support for disaster recovery
- **Data validation**: Regular integrity checks

This normalized schema provides a solid foundation for the enterprise-scale requirements while maintaining data integrity, performance, and security.
