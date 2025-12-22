## Here are few logs in different scenarios, in our application we have 2 types of user -> USER, ADMIN. ADMIN has access to some of the protected apis, while user has access to other apis. In this case I logged in as a USER and tried to access an ADMIN API, then got 403, below is complete explanation for it.

### Problem
A user with role `USER` logs in successfully but receives **403 Forbidden** when accessing an endpoint restricted to `ADMIN`.

---

### Observed Logs (Login + Restricted API Access)

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

### Security Configuration Involved

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

### How this works behind the scenes (Step-by-step)

Spring Security applies **two layers of authorization**:

| Layer        | Purpose                                  |
| ------------ | ---------------------------------------- |
| URL-level    | Can this request reach application code? |
| Method-level | Can this user perform this action?       |

In this case, the request was **blocked at URL-level**.

---

### Request Lifecycle (Mapped to Logs)

### 1. Request enters Tomcat

```
Postman → GET /api/v1/users
```

* Tomcat accepts request
* Assigns a request thread

---

### 2. Spring Security Filter Chain starts

```text
Securing GET /api/v1/users
```

---

### 3. SecurityContext is loaded from HttpSession

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

### 4. URL-level authorization check (`requestMatchers`)

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

### 5. Access denied at FILTER layer

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

### Why 403 and not 401?

| Status | Meaning                          |
| ------ | -------------------------------- |
| 401    | Not authenticated                |
| 403    | Authenticated but not authorized |

The user **was authenticated**, but **did not have ROLE_ADMIN** → **403 is correct**

---

### Final Summary

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

## /login - incorrect login logs
```log
2025-12-22T19:30:42.449+05:30  INFO 15917 --- [auth-service] [nio-8080-exec-2] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2025-12-22T19:30:42.449+05:30  INFO 15917 --- [auth-service] [nio-8080-exec-2] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2025-12-22T19:30:42.450+05:30  INFO 15917 --- [auth-service] [nio-8080-exec-2] o.s.web.servlet.DispatcherServlet        : Completed initialization in 1 ms
2025-12-22T19:30:42.457+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'filterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, JwtAuthentication, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-22T19:30:42.458+05:30 DEBUG 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Securing POST /api/v1/auth/jwt/login
2025-12-22T19:30:42.458+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/12)
2025-12-22T19:30:42.458+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/12)
2025-12-22T19:30:42.459+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/12)
2025-12-22T19:30:42.460+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/12)
2025-12-22T19:30:42.460+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/12)
2025-12-22T19:30:42.460+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-22T19:30:42.461+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking JwtAuthenticationFilter (6/12)
2025-12-22T19:30:42.461+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (7/12)
2025-12-22T19:30:42.461+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (8/12)
2025-12-22T19:30:42.461+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (9/12)
2025-12-22T19:30:42.462+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (10/12)
2025-12-22T19:30:42.462+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-22T19:30:42.463+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to AnonymousAuthenticationToken [Principal=anonymousUser, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_ANONYMOUS]]
2025-12-22T19:30:42.463+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (11/12)
2025-12-22T19:30:42.463+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (12/12)
2025-12-22T19:30:42.463+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] estMatcherDelegatingAuthorizationManager : Authorizing POST /api/v1/auth/jwt/login
2025-12-22T19:30:42.463+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] estMatcherDelegatingAuthorizationManager : Checking authorization on POST /api/v1/auth/jwt/login using org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer$$Lambda$1525/0x00000070019e8000@4f3688de
2025-12-22T19:30:42.464+05:30 DEBUG 15917 --- [auth-service] [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Secured POST /api/v1/auth/jwt/login
2025-12-22T19:30:42.483+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.s.authentication.ProviderManager     : Authenticating request with DaoAuthenticationProvider (1/1)
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
2025-12-22T19:30:42.672+05:30 DEBUG 15917 --- [auth-service] [nio-8080-exec-2] o.s.s.a.dao.DaoAuthenticationProvider    : Failed to authenticate since password does not match stored value
2025-12-22T19:30:42.675+05:30 TRACE 15917 --- [auth-service] [nio-8080-exec-2] o.s.s.w.a.ExceptionTranslationFilter     : Sending to authentication entry point since authentication failed

org.springframework.security.authentication.BadCredentialsException: Bad credentials
...
...
```

---

## /login - correct login logs
CURL ->
```
postman request POST 'localhost:8080/api/v1/auth/jwt/login' \
  --header 'Content-Type: application/json' \
  --body '{
  "email": "<user-email>@gmail.com",
  "password": "<user-password>"
}'
```

```log
2025-12-22T19:35:46.786+05:30  INFO 16758 --- [auth-service] [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2025-12-22T19:35:46.786+05:30  INFO 16758 --- [auth-service] [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2025-12-22T19:35:46.787+05:30  INFO 16758 --- [auth-service] [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 1 ms
2025-12-22T19:35:46.793+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'filterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, JwtAuthentication, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-22T19:35:46.794+05:30 DEBUG 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Securing POST /api/v1/auth/jwt/login
2025-12-22T19:35:46.794+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/12)
2025-12-22T19:35:46.794+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/12)
2025-12-22T19:35:46.795+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/12)
2025-12-22T19:35:46.796+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/12)
2025-12-22T19:35:46.796+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/12)
2025-12-22T19:35:46.796+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-22T19:35:46.796+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking JwtAuthenticationFilter (6/12)
2025-12-22T19:35:46.797+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (7/12)
2025-12-22T19:35:46.797+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (8/12)
2025-12-22T19:35:46.797+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (9/12)
2025-12-22T19:35:46.797+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (10/12)
2025-12-22T19:35:46.797+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-22T19:35:46.798+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to AnonymousAuthenticationToken [Principal=anonymousUser, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_ANONYMOUS]]
2025-12-22T19:35:46.798+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (11/12)
2025-12-22T19:35:46.798+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (12/12)
2025-12-22T19:35:46.798+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Authorizing POST /api/v1/auth/jwt/login
2025-12-22T19:35:46.799+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Checking authorization on POST /api/v1/auth/jwt/login using org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer$$Lambda$1524/0x00000070019e6d50@353b35bd
2025-12-22T19:35:46.799+05:30 DEBUG 16758 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Secured POST /api/v1/auth/jwt/login
2025-12-22T19:35:46.813+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.s.authentication.ProviderManager     : Authenticating request with DaoAuthenticationProvider (1/1)
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
2025-12-22T19:35:47.006+05:30 DEBUG 16758 --- [auth-service] [nio-8080-exec-1] o.s.s.a.dao.DaoAuthenticationProvider    : Authenticated user
2025-12-22T19:35:47.034+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-1] o.s.s.w.header.writers.HstsHeaderWriter  : Not injecting HSTS header since it did not match request to [Is Secure]
```

---

## /logout - logs
```log
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'filterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, JwtAuthentication, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-22T19:38:19.135+05:30 DEBUG 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Securing POST /api/v1/auth/jwt/logout
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/12)
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/12)
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/12)
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/12)
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/12)
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-22T19:38:19.135+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking JwtAuthenticationFilter (6/12)
2025-12-22T19:38:19.143+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-22T19:38:19.143+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (7/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (8/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (9/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (10/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.s.w.a.AnonymousAuthenticationFilter  : Did not set SecurityContextHolder since already authenticated UsernamePasswordAuthenticationToken [Principal=anand.ankita.96@gmail.com, Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] s.CompositeSessionAuthenticationStrategy : Preparing session with ChangeSessionIdAuthenticationStrategy (1/1)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (11/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (12/12)
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] estMatcherDelegatingAuthorizationManager : Authorizing POST /api/v1/auth/jwt/logout
2025-12-22T19:38:19.144+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] estMatcherDelegatingAuthorizationManager : Checking authorization on POST /api/v1/auth/jwt/logout using org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer$$Lambda$1524/0x00000070019e6d50@353b35bd
2025-12-22T19:38:19.145+05:30 DEBUG 16758 --- [auth-service] [nio-8080-exec-4] o.s.security.web.FilterChainProxy        : Secured POST /api/v1/auth/jwt/logout
2025-12-22T19:38:19.151+05:30 TRACE 16758 --- [auth-service] [nio-8080-exec-4] o.s.s.w.header.writers.HstsHeaderWriter  : Not injecting HSTS header since it did not match request to [Is Secure]
```

---

## loggedIn user, trying to access unauthorized resource
CURL ->
```
postman request 'localhost:8080/api/v1/users/email/bhaskar123u@gmail.com' \
  --header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlMGU0MmNmOS1hMmRjLTQzNzctYTk5MC03ZTU0NWYyM2EyOWYiLCJyb2xlcyI6WyJST0xFX1VTRVIiXSwiZXhwIjoxNzY2NDEzNTgyLCJpYXQiOjE3NjY0MTI2ODIsImVtYWlsIjoiYW5hbmQuYW5raXRhLjk2QGdtYWlsLmNvbSJ9.quNvuw6V2JbNsHBZc9EEYt16CEHsNjLWtwGjnrFkm3VJJ3FyWr0j7DEEUsRSW+9bUuKbtY4ync1Z61wgVq3sGb3SyUz2XD6J326u6DmXV7jNvrQDsZi/RrY9/khDAHJ0z6Spz6GtotORCfrKXMkPDH2RgXGsss/pFTnEVfb4zsKwA6lqIBnKzCZMDKRBPnQVCVl+My+F/Q37dvykqbt2XAcBTEsBZ3keRJILIOCodt9cKdwzgDMFX5wFF91F3Z6cPTbYEXaSWybUiheLlFMqa9Vwpy4u8cCvuZ992KHADWa4MSw+a/cBFnqGkj7GTwf2MOm5VadKUna4sdAF9rS+6g==' \
  --auth-bearer-token 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlMGU0MmNmOS1hMmRjLTQzNzctYTk5MC03ZTU0NWYyM2EyOWYiLCJyb2xlcyI6WyJST0xFX1VTRVIiXSwiZXhwIjoxNzY2NDEzNTgyLCJpYXQiOjE3NjY0MTI2ODIsImVtYWlsIjoiYW5hbmQuYW5raXRhLjk2QGdtYWlsLmNvbSJ9.quNvuw6V2JbNsHBZc9EEYt16CEHsNjLWtwGjnrFkm3VJJ3FyWr0j7DEEUsRSW+9bUuKbtY4ync1Z61wgVq3sGb3SyUz2XD6J326u6DmXV7jNvrQDsZi/RrY9/khDAHJ0z6Spz6GtotORCfrKXMkPDH2RgXGsss/pFTnEVfb4zsKwA6lqIBnKzCZMDKRBPnQVCVl+My+F/Q37dvykqbt2XAcBTEsBZ3keRJILIOCodt9cKdwzgDMFX5wFF91F3Z6cPTbYEXaSWybUiheLlFMqa9Vwpy4u8cCvuZ992KHADWa4MSw+a/cBFnqGkj7GTwf2MOm5VadKUna4sdAF9rS+6g=='
```
```log
2025-12-22T19:41:39.754+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'filterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, JwtAuthentication, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-22T19:41:39.755+05:30 DEBUG 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Securing GET /api/v1/users/email/bhaskar123u@gmail.com
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/12)
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/12)
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/12)
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/12)
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/12)
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-22T19:41:39.755+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking JwtAuthenticationFilter (6/12)
2025-12-22T19:41:39.762+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-22T19:41:39.762+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (7/12)
2025-12-22T19:41:39.762+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (8/12)
2025-12-22T19:41:39.762+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (9/12)
2025-12-22T19:41:39.762+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (10/12)
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.s.w.a.AnonymousAuthenticationFilter  : Did not set SecurityContextHolder since already authenticated UsernamePasswordAuthenticationToken [Principal=anand.ankita.96@gmail.com, Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] s.CompositeSessionAuthenticationStrategy : Preparing session with ChangeSessionIdAuthenticationStrategy (1/1)
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (11/12)
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (12/12)
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] estMatcherDelegatingAuthorizationManager : Authorizing GET /api/v1/users/email/bhaskar123u@gmail.com
2025-12-22T19:41:39.763+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] estMatcherDelegatingAuthorizationManager : Checking authorization on GET /api/v1/users/email/bhaskar123u@gmail.com using org.springframework.security.authorization.AuthenticatedAuthorizationManager@3c820320
2025-12-22T19:41:39.763+05:30 DEBUG 18509 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Secured GET /api/v1/users/email/bhaskar123u@gmail.com
2025-12-22T19:41:39.768+05:30 DEBUG 18509 --- [auth-service] [nio-8080-exec-3] horizationManagerBeforeMethodInterceptor : Authorizing method invocation ReflectiveMethodInvocation: public org.springframework.http.ResponseEntity com.bsharan.auth_service.controllers.UserController.getUserByEmail(java.lang.String); target is of class [com.bsharan.auth_service.controllers.UserController]
2025-12-22T19:41:39.774+05:30 DEBUG 18509 --- [auth-service] [nio-8080-exec-3] horizationManagerBeforeMethodInterceptor : Failed to authorize ReflectiveMethodInvocation: public org.springframework.http.ResponseEntity com.bsharan.auth_service.controllers.UserController.getUserByEmail(java.lang.String); target is of class [com.bsharan.auth_service.controllers.UserController] with authorization manager org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager@77a18b10 and result ExpressionAuthorizationDecision [granted=false, expressionAttribute=    hasRole('ADMIN') or
    #email == authentication.name
]
2025-12-22T19:41:39.777+05:30 TRACE 18509 --- [auth-service] [nio-8080-exec-3] o.s.s.w.a.ExceptionTranslationFilter     : Sending UsernamePasswordAuthenticationToken [Principal=anand.ankita.96@gmail.com, Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]] to access denied handler since access is denied

org.springframework.security.authorization.AuthorizationDeniedException: Access Denied
...
...
```

---

## loggedIn user, trying to access authorized resource (success)
```log
2025-12-22T19:45:23.299+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'filterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, JwtAuthentication, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-22T19:45:23.300+05:30 DEBUG 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Securing GET /api/v1/users/email/anand.ankita.96@gmail.com
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/12)
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/12)
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/12)
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/12)
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/12)
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-22T19:45:23.300+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking JwtAuthenticationFilter (6/12)
2025-12-22T19:45:23.308+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-22T19:45:23.308+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (7/12)
2025-12-22T19:45:23.308+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (8/12)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (9/12)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (10/12)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.s.w.a.AnonymousAuthenticationFilter  : Did not set SecurityContextHolder since already authenticated UsernamePasswordAuthenticationToken [Principal=anand.ankita.96@gmail.com, Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] s.CompositeSessionAuthenticationStrategy : Preparing session with ChangeSessionIdAuthenticationStrategy (1/1)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (11/12)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (12/12)
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] estMatcherDelegatingAuthorizationManager : Authorizing GET /api/v1/users/email/anand.ankita.96@gmail.com
2025-12-22T19:45:23.309+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] estMatcherDelegatingAuthorizationManager : Checking authorization on GET /api/v1/users/email/anand.ankita.96@gmail.com using org.springframework.security.authorization.AuthenticatedAuthorizationManager@6b4d8050
2025-12-22T19:45:23.310+05:30 DEBUG 19279 --- [auth-service] [nio-8080-exec-3] o.s.security.web.FilterChainProxy        : Secured GET /api/v1/users/email/anand.ankita.96@gmail.com
2025-12-22T19:45:23.314+05:30 DEBUG 19279 --- [auth-service] [nio-8080-exec-3] horizationManagerBeforeMethodInterceptor : Authorizing method invocation ReflectiveMethodInvocation: public org.springframework.http.ResponseEntity com.bsharan.auth_service.controllers.UserController.getUserByEmail(java.lang.String); target is of class [com.bsharan.auth_service.controllers.UserController]
2025-12-22T19:45:23.319+05:30 DEBUG 19279 --- [auth-service] [nio-8080-exec-3] horizationManagerBeforeMethodInterceptor : Authorized method invocation ReflectiveMethodInvocation: public org.springframework.http.ResponseEntity com.bsharan.auth_service.controllers.UserController.getUserByEmail(java.lang.String); target is of class [com.bsharan.auth_service.controllers.UserController]
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
2025-12-22T19:45:23.342+05:30 TRACE 19279 --- [auth-service] [nio-8080-exec-3] o.s.s.w.header.writers.HstsHeaderWriter  : Not injecting HSTS header since it did not match request to [Is Secure]
```