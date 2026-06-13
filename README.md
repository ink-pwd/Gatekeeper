# GateKeeper

Gatekeeper is a production-oriented authentication microservice written in Go.

The service provides user registration, email verification, authentication, JWT generation, and token validation through a REST API. User data is stored in PostgreSQL, verification tokens are temporarily stored in Redis, and passwords are securely hashed using bcrypt.

## Features

* User registration
* Email verification workflow
* Secure password hashing with bcrypt
* JWT authentication
* JWT validation endpoint
* PostgreSQL integration
* Redis integration
* UUID-based verification tokens
* Automatic cleanup of unverified users
* SMTP email delivery
* Docker containerization
* Docker Compose orchestration
* Environment-based configuration
* Structured logging

---

## Architecture

### Registration Flow

1. User submits email and password.
2. Password is hashed using bcrypt.
3. User is stored in PostgreSQL with `verify = false`.
4. A unique UUID verification token is generated.
5. UUID → Email mapping is stored in Redis with TTL.
6. Verification link is sent via email.
7. User confirms email using the verification endpoint.
8. Account status is updated to verified.

### Authentication Flow

1. User sends email and password.
2. Password is verified against bcrypt hash.
3. Only verified accounts can authenticate.
4. Service generates a signed JWT token.
5. Token can be validated through a dedicated endpoint.

---

## Tech Stack

| Component        | Technology     |
| ---------------- | -------------- |
| Language         | Go             |
| Database         | PostgreSQL     |
| Cache            | Redis          |
| Authentication   | JWT            |
| Password Hashing | bcrypt         |
| Email Delivery   | SMTP           |
| Containerization | Docker         |
| Orchestration    | Docker Compose |

---

## API Endpoints

### Register User

```http
POST /auth/register
```

Request:

```json
{
  "email": "user@example.com",
  "password": "strongpassword"
}
```

Response:

```http
200 OK
```

A verification email will be sent to the specified address.

---

### Verify Email

```http
GET /verify?token=<uuid>
```

Response:

```http
200 OK
```

The account becomes verified and can now authenticate.

---

### Login

```http
POST /auth/login
```

Request:

```json
{
  "email": "user@example.com",
  "password": "strongpassword"
}
```

Response:

```json
{
  "token": "<jwt-token>"
}
```

---

### Validate JWT

```http
GET /auth/validate
```

Headers:

```http
Authorization: Bearer <jwt-token>
```

Response:

```json
{
  "email": "user@example.com",
  "valid": "true"
}
```

---

## Running with Docker Compose

Build and start all services:

```bash
docker compose up --build
```

Services started:

* Gatekeeper API
* PostgreSQL
* Redis

---

## Security Features

* bcrypt password hashing
* JWT signature validation
* Email verification before login
* Temporary verification tokens stored in Redis
* UUID-based verification links
* Automatic removal of inactive unverified accounts
* Environment-based secrets management

---

## Project Structure

```text
Gatekeeper/
├── cmd/
│   └── api-server/
│       └── main.go
│
├── internal/
│   ├── consts/
│       └── const.go
│   ├── email/
│       └── sender.go
│   ├── handler/
│       └── handler.go
│   ├── model/
│       └── user.go
│   ├── security/
│       └── hash.go
│       └── jwt.go
│       └── uuid.go
│   └── storage/
│       └── migration.sql
│       └── postgres.go
│       └── redis.go
│
├── logger/
│       └── logger.go
│
├── .env
├── docker-compose.yml
├── dockerfile
├── go.mod
└── README.md
```

---

## Purpose

Gatekeeper was created as a learning project focused on backend development with Go.

The project demonstrates practical usage of:

* REST APIs
* PostgreSQL
* Redis
* JWT authentication
* SMTP integration
* Password hashing
* Docker
* Docker Compose
* Clean project structure
* Dependency separation
* Authentication microservice architecture
