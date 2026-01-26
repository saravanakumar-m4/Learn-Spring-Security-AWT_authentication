🔐 Spring Boot JWT Authentication using OAuth2 Resource Server

This project demonstrates JWT-based authentication using Spring Security OAuth2 Resource Server.
It combines Authorization Server + Resource Server in one application only for learning purposes.

🚀 Features

- In-memory users

- JWT token generation

- RSA Public / Private key signing

- Stateless authentication

- /jwt endpoint to generate token

- OAuth2 Resource Server for API protection

👤 Default Users

- One User and one Admin user

🔐 Authentication Flow

Client → Basic Auth Login → /jwt → Receive JWT →
Send JWT in Authorization header → Access secured APIs

🔑 Generate JWT Token
Request
GET /jwt
Authorization: Basic sk:dummy

Response
{
  "name": "eyJhbGciOiJSUzI1NiIs..."
}

🔁 Access Protected API
GET /test
Authorization: Bearer <JWT_TOKEN>

🧾 JWT ClaimSet
{
  "iss": "self",
  "sub": "sk",
  "iat": 1705060000,
  "exp": 1705060900,
  "scope": "ROLE_USER"
}

⚙ Security Configuration Summary

Configuration	Purpose
authenticated()	Secures all endpoints
STATELESS	No sessions
httpBasic()	Used only to generate JWT
oauth2ResourceServer().jwt()	Enables JWT validation
csrf().disable()	Not required for JWT
🧠 Learning Note

This project is built for educational purposes.
In real-world systems:

Authorization Server

Resource Server

must be separate applications.
