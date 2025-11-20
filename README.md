# 🔐 Auth Service - Secure Microservice Authentication

![Java](https://img.shields.io/badge/Java-21-orange?style=for-the-badge&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.4.0-green?style=for-the-badge&logo=spring-boot)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)
![Security](https://img.shields.io/badge/JWT-RS256-red?style=for-the-badge)

## 🚀 Project Overview

I built this **Authentication Service** to serve as the secure backbone for a distributed microservices architecture. It handles identity management, secure user registration, and stateless authentication using **JSON Web Tokens (JWT)** signed with **RSA asymmetric cryptography**.

This project demonstrates my ability to build **production-ready, cloud-native applications** that prioritize security, scalability, and clean configuration management.

## 🛠️ Tech Stack

I chose a modern, enterprise-grade stack to ensure performance and maintainability:

- **Core:** Java 21 LTS, Spring Boot 3.4.0
- **Database:** PostgreSQL (Hosted/Cloud Ready)
- **Security:** Spring Security, RSA (RS256) Signatures, BCrypt Password Hashing
- **Containerization:** Docker & Docker Compose
- **Build Tool:** Maven

## ✨ Key Features

- **Stateless Authentication:** Issues self-contained JWTs signed with a private RSA key.
- **Asymmetric Security:** Public keys can be shared with other microservices to validate tokens without exposing the private signing key.
- **Environment-Based Config:** Fully externalized configuration following the **12-Factor App methodology**. No secrets are hardcoded.
- **Docker Orchestration:** One-command startup for the application and its database dependencies.
- **Resilient Database Connection:** Configured for hosted PostgreSQL databases with connection pooling.

## 📂 Project Structure

I organized the project to separate concerns and ensure sensitive data never leaks to version control:

```bash
auth-service/
├── src/main/java       # Application logic
├── src/main/resources  # Configuration
├── keys/               # (Local Only) RSA Keypairs for signing
├── .env.example        # Template for environment variables
├── Dockerfile          # Optimized Java 21 container build
└── docker-compose.yml  # Local development orchestration


git clone <your-repo-url>
cd auth-service

# Create your local environment file from the template
cp .env.example .env

# Create keys directory
mkdir -p src/main/resources/keys

# Generate Private Key
openssl genrsa -out src/main/resources/keys/private_key.pem 2048

# Generate Public Key
openssl rsa -in src/main/resources/keys/private_key.pem -pubout -out src/main/resources/keys/public_key.pem


docker-compose up --build


Created by Tejas R
```
