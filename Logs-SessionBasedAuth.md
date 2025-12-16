## Q1. I logged in as a USER and tried to access an ADMIN API. Why did I get 403?

### ❓ Problem

A user with role `USER` logs in successfully but receives **403 Forbidden** when accessing an endpoint restricted to `ADMIN`.

---

## 🔍 Observed Logs (Login + Restricted API Access)

### Login (`POST /login`)

```text
DaoAuthenticationProvider : Authenticated user
Stored SecurityContextImpl ... to HttpSession
Set SecurityContextHolder to UsernamePasswordAuthenticationToken
```

Key outcome:

* User authenticated successfully
* Authorities: `[ROLE_USER]`
* SecurityContext stored in **HttpSession**

---

### Restricted API (`GET /api/v1/users`)

```text
Securing GET /api/v1/users
Authorizing GET /api/v1/users
Checking authorization using AuthorityAuthorizationManager[authorities=[ROLE_ADMIN]]
Retrieved SecurityContextImpl
ExceptionTranslationFilter : Sending Authentication to access denied handler
AuthorizationDeniedException: Access Denied
```

---

## 🔐 Security Configuration Involved

### Controller (Method-level security)

```java
@GetMapping
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Iterable<UserDto>> getAllUsers() {
    return ResponseEntity.status(HttpStatus.OK).body(userService.getAllUsers());
}
```

### Security Filter Chain (URL-level security)

```java
.requestMatchers("/api/v1/users").hasRole("ADMIN")
```

---

## 🧠 How this works behind the scenes (Step-by-step)

Spring Security applies **two layers of authorization**:

| Layer        | Purpose                                  |
| ------------ | ---------------------------------------- |
| URL-level    | Can this request reach application code? |
| Method-level | Can this user perform this action?       |

In this case, the request was **blocked at URL-level**.

---

## 🧭 Request Lifecycle (Mapped to Logs)

### 1️⃣ Request enters Tomcat

```
Postman → GET /api/v1/users
```

* Tomcat accepts request
* Assigns a request thread

---

### 2️⃣ Spring Security Filter Chain starts

```text
Securing GET /api/v1/users
```

---

### 3️⃣ SecurityContext is loaded from HttpSession

```text
Retrieved SecurityContextImpl
```

Internally, this happens:

```java
SecurityContext context =
    httpSession.getAttribute("SPRING_SECURITY_CONTEXT");
SecurityContextHolder.setContext(context);
```

At this point, **ThreadLocal contains**:

```
SecurityContext
 └── Authentication
      ├── authenticated = true
      └── authorities = [ROLE_USER]
```

---

### 4️⃣ URL-level authorization check (`requestMatchers`)

```text
Checking authorization using AuthorityAuthorizationManager[authorities=[ROLE_ADMIN]]
```

Spring compares:

| Required     | Present     |
| ------------ | ----------- |
| `ROLE_ADMIN` | `ROLE_USER` |

Comparison logic (simplified):

```java
authentication.getAuthorities().contains("ROLE_ADMIN")
```

❌ **No match**

---

### 5️⃣ Access denied at FILTER layer

```text
ExceptionTranslationFilter : Sending Authentication to access denied handler
```

Spring throws:

```
AuthorizationDeniedException
```

Response sent to client:

```
HTTP 403 Forbidden
```

---

## ❗ Important Observations

### ❌ Controller was never executed

* `DispatcherServlet` not reached
* `@PreAuthorize` **never evaluated**

This confirms:

> ❗ The request was blocked **before application code**, at URL-level authorization.

---

## 🤔 Why 403 and not 401?

| Status | Meaning                          |
| ------ | -------------------------------- |
| 401    | Not authenticated                |
| 403    | Authenticated but not authorized |

The user **was authenticated**, but **did not have ROLE_ADMIN** → **403 is correct**

---

## 📌 Final Summary

```
Client
 ↓
Tomcat
 ↓
Security Filter Chain
 ├── Authentication ✅ (from HttpSession)
 ├── URL Authorization ❌ (ROLE_ADMIN required)
 ↓
ExceptionTranslationFilter
 ↓
403 Forbidden
```

---

## /logout - logs
2025-12-14T20:05:15.034+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-8] o.s.security.web.FilterChainProxy        : Securing POST /logout
2025-12-14T20:05:15.034+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-8] w.c.HttpSessionSecurityContextRepository : Retrieved SecurityContextImpl [Authentication=UsernamePasswordAuthenticationToken [Principal=org.springframework.security.core.userdetails.User [Username=anand.ankita.96@gmail.com, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, CredentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_USER]], Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_USER]]]
2025-12-14T20:05:15.034+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-8] o.s.s.w.a.logout.LogoutFilter            : Logging out [UsernamePasswordAuthenticationToken [Principal=org.springframework.security.core.userdetails.User [Username=anand.ankita.96@gmail.com, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, CredentialsNonExpired=true, AccountNonLocked=true, Granted Authorities=[ROLE_USER]], Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_USER]]]
2025-12-14T20:05:15.035+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-8] o.s.s.w.a.l.SecurityContextLogoutHandler : Invalidated session 244E5DFD4047CF0AAEB9B630ED1E2B90

---

## /login - incorrect login logs
POST /login
Hibernate: 
    select
        u1_0.user_id,
        u1_0.created_at,
        u1_0.email,
        u1_0.enabled,
        u1_0.image,
        u1_0.name,
        u1_0.password,
        u1_0.provider,
        u1_0.updated_at 
    from
        users u1_0 
    where
        u1_0.email=?
Hibernate: 
    select
        r1_0.user_id,
        r1_0.role 
    from
        user_roles r1_0 
    where
        r1_0.user_id=?
2025-12-14T20:06:49.688+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-1] o.s.s.a.dao.DaoAuthenticationProvider    : Failed to authenticate since password does not match stored value
2025-12-14T20:06:49.691+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Securing POST /error
2025-12-14T20:06:49.691+05:30 TRACE 38959 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Authorizing POST /error
2025-12-14T20:06:49.691+05:30 TRACE 38959 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Checking authorization on POST /error using org.springframework.security.authorization.AuthenticatedAuthorizationManager@3428e1ad
2025-12-14T20:06:49.691+05:30 DEBUG 38959 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to anonymous SecurityContext
2025-12-14T20:06:49.691+05:30 TRACE 38959 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.ExceptionTranslationFilter     : Sending AnonymousAuthenticationToken [Principal=anonymousUser, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_ANONYMOUS]] to authentication entry point since access is denied

org.springframework.security.authorization.AuthorizationDeniedException: Access Denied

