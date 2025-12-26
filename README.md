# 🔐 security-common  
Reusable Spring Security & JWT Library for Microservices

---

## 📌 Overview

`security-common` is a **production-grade Spring Security common library** designed for **Spring Boot microservice architectures**.

It centralizes **authentication and authorization infrastructure** so that individual microservices can focus purely on **business logic**, while security concerns are handled **consistently and correctly** across the platform.

Typical consumers:
- User / Auth Service
- Item Service
- Cart Service
- Payment Service
- Order Service

---

## 🎯 Objectives

- Eliminate duplicated Spring Security code across services
- Provide consistent JWT-based authentication
- Support role-based authorization
- Enable stateless, scalable security
- Keep security completely **business-agnostic**

---

## 🧠 Architectural Principle

> **This library provides SECURITY MECHANISM, not SECURITY POLICY**

- **Mechanism** → JWT parsing, validation, filters, security context
- **Policy** → Authorization rules (`@PreAuthorize`, endpoint access) are defined per service

---

## ✨ Features

### Authentication
- Stateless JWT authentication
- Token extraction from:
  - `Authorization: Bearer <token>` header
  - HTTP cookies
- Token validation and expiration handling

### Authorization
- Role-based authorization (`ROLE_USER`, `ROLE_ADMIN`)
- Method-level security support
- Spring Security context propagation

### Infrastructure
- Auto-configured `SecurityFilterChain`
- Custom JWT `OncePerRequestFilter`
- BCrypt password encoder
- Spring Boot 3.x compatible
- Java 21 compatible

---

## 🚫 Explicit Non-Goals

This library intentionally **does NOT**:
- Define `User` entities
- Access any database
- Provide auth controllers (`/login`, `/signup`)
- Persist refresh tokens
- Enforce business-specific authorization rules

These responsibilities belong to **individual microservices**.

---

## 📦 Installation

### Maven Dependency

```xml
<dependency>
    <groupId>com.cts.security</groupId>
    <artifactId>security-common</artifactId>
    <version>1.0.0</version>
</dependency>
