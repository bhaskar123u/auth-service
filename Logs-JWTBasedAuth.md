### Below are logs and explainations for JWT based auth

---

## When user logs in with useremail and password for the 1st time
```json
requestBody {
    "email": "anand.ankita.96@gmail.com",
    "password": "12345678"
}

responseBody {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoLXNlcnZpY2UiLCJlbWFpbCI6ImFuYW5kLmFua2l0YS45NkBnbWFpbC5jb20iLCJpYXQiOjE3NjYyOTQ1MDUsInN1YiI6ImUwZTQyY2Y5LWEyZGMtNDM3Ny1hOTkwLTdlNTQ1ZjIzYTI5ZiIsImV4cCI6MTc2NjI5NTQwNSwicm9sZXMiOlsiUk9MRV9VU0VSIl19.xLNgcKhVDJN7WtHlWGAxsVlv0JifMCJd3y1U1-LtJVaej41VI7C927V-lTJMsGLX90AZUQJujh5SnvmxDvRT0g0DqqrrclLJx9zhsgpABjs4AEX5H51JgspBdtZsV2LL8Dt90B4VlhGZhfSmuCZ42sgdPccceXoy_18wke3pL2gbLFvSx-UKiLOg5iNiLoZU51m-QT5WlO-p2hnLMvUT5YV9IB87RtFQROAGTBfJMpVm7xakh481ktzvA4-qo9uO4cM52dmeOkTag3bGhFNDkkWiCUcgl2-4681oyh6FPfhoMFiQOPEC5Ybmwm3UPqlaian9XrkgYQ_TgWLfQRDb3A",
    "tokenType": "Bearer",
    "expiresAt": 1766295405
}
```
We get the following logs for this action -->
```text
2025-12-21T10:51:45.414+05:30  INFO 69303 --- [auth-service] [nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring DispatcherServlet 'dispatcherServlet'
2025-12-21T10:51:45.414+05:30  INFO 69303 --- [auth-service] [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Initializing Servlet 'dispatcherServlet'
2025-12-21T10:51:45.415+05:30  INFO 69303 --- [auth-service] [nio-8080-exec-1] o.s.web.servlet.DispatcherServlet        : Completed initialization in 1 ms
2025-12-21T10:51:45.421+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Trying to match request against DefaultSecurityFilterChain defined as 'jwtSecurityFilterChain' in [class path resource [com/bsharan/auth_service/jwtSecurity/configs/JwtSecurityConfig.class]] matching [any request] and having filters [DisableEncodeUrl, WebAsyncManagerIntegration, SecurityContextHolder, HeaderWriter, Logout, RequestCacheAware, SecurityContextHolderAwareRequest, AnonymousAuthentication, SessionManagement, ExceptionTranslation, Authorization] (1/1)
2025-12-21T10:51:45.422+05:30 DEBUG 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Securing POST /api/v1/auth/jwt/login
2025-12-21T10:51:45.422+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking DisableEncodeUrlFilter (1/11)
2025-12-21T10:51:45.423+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking WebAsyncManagerIntegrationFilter (2/11)
2025-12-21T10:51:45.423+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderFilter (3/11)
2025-12-21T10:51:45.424+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking HeaderWriterFilter (4/11)
2025-12-21T10:51:45.424+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking LogoutFilter (5/11)
2025-12-21T10:51:45.424+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.logout.LogoutFilter            : Did not match request to Or [Ant [pattern='/logout', GET], Ant [pattern='/logout', POST], Ant [pattern='/logout', PUT], Ant [pattern='/logout', DELETE]]
2025-12-21T10:51:45.425+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking RequestCacheAwareFilter (6/11)
2025-12-21T10:51:45.425+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SecurityContextHolderAwareRequestFilter (7/11)
2025-12-21T10:51:45.425+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking AnonymousAuthenticationFilter (8/11)
2025-12-21T10:51:45.425+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking SessionManagementFilter (9/11)
2025-12-21T10:51:45.425+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] .s.s.w.c.SupplierDeferredSecurityContext : Created SecurityContextImpl [Null authentication]
2025-12-21T10:51:45.426+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to AnonymousAuthenticationToken [Principal=anonymousUser, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=0:0:0:0:0:0:0:1, SessionId=null], Granted Authorities=[ROLE_ANONYMOUS]]
2025-12-21T10:51:45.426+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking ExceptionTranslationFilter (10/11)
2025-12-21T10:51:45.426+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Invoking AuthorizationFilter (11/11)
2025-12-21T10:51:45.426+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Authorizing POST /api/v1/auth/jwt/login
2025-12-21T10:51:45.426+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] estMatcherDelegatingAuthorizationManager : Checking authorization on POST /api/v1/auth/jwt/login using org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer$$Lambda$1566/0x0000000401a0f160@66c90ffb
2025-12-21T10:51:45.427+05:30 DEBUG 69303 --- [auth-service] [nio-8080-exec-1] o.s.security.web.FilterChainProxy        : Secured POST /api/v1/auth/jwt/login
AUTH HEADER = null
2025-12-21T10:51:45.440+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.s.authentication.ProviderManager     : Authenticating request with DaoAuthenticationProvider (1/1)
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
2025-12-21T10:51:45.610+05:30 DEBUG 69303 --- [auth-service] [nio-8080-exec-1] o.s.s.a.dao.DaoAuthenticationProvider    : Authenticated user
2025-12-21T10:51:45.631+05:30 TRACE 69303 --- [auth-service] [nio-8080-exec-1] o.s.s.w.header.writers.HstsHeaderWriter  : Not injecting HSTS header since it did not match request to [Is Secure]
```

Filter invoking order
```text
Invoking DisableEncodeUrlFilter
Invoking WebAsyncManagerIntegrationFilter
Invoking SecurityContextHolderFilter
Invoking HeaderWriterFilter
Invoking LogoutFilter
Invoking RequestCacheAwareFilter
Invoking SecurityContextHolderAwareRequestFilter
Invoking AnonymousAuthenticationFilter
Invoking SessionManagementFilter
Invoking ExceptionTranslationFilter
Invoking AuthorizationFilter
```
Explaination of each filter

1. DisableEncodeUrlFilter

Input : HttpServletRequest`, `HttpServletResponse`

What it does
- Disables URL rewriting (`;jsessionid=...`)
- Ensures session ID is **never appended to URLs**

Output
- Same request/response, but URL encoding is blocked
  ✔ Security hardening

---

2. WebAsyncManagerIntegrationFilter

Input : Request entering async-capable controller (`@Async`, `DeferredResult`, `CompletableFuture`)

What it does
- Binds `SecurityContext` to Spring’s async thread model
- Ensures auth info survives thread switches

Output
- Request with `SecurityContext` safely propagated across threads

---

3. SecurityContextHolderFilter

Input : Incoming HTTP request

What it does
- Loads `SecurityContext` (from session / deferred supplier)
- Places it into `SecurityContextHolder` (ThreadLocal)

Output
- Thread now has a `SecurityContext` (initially empty)

---

4. HeaderWriterFilter

Input : Request + Response

What it does
- Adds security headers (`X-Frame-Options`, `X-Content-Type-Options`, HSTS if HTTPS)

Output
- Response with security headers added
  (No auth decision here)

---

5. LogoutFilter

Input : Request path + HTTP method

What it does
- Checks if request matches `/logout`
- If matched → clears SecurityContext, invalidates session

Output
- ❌ Not matched → passes request untouched
  ✔ In your logs: **skipped**

---

6. RequestCacheAwareFilter

Input : Request + SecurityContext

What it does
- If request is unauthenticated & protected → caches request
- Used for redirect-after-login (form login)

Output : For JWT APIs → mostly a NO-OP

---

7. SecurityContextHolderAwareRequestFilter

Input : Request + SecurityContext

What it does
- Wraps `HttpServletRequest`
- Enables APIs like:
  * `request.getUserPrincipal()`
  * `request.isUserInRole()`

Output
- Wrapped request with security-aware methods

---

8. AnonymousAuthenticationFilter

Input : Request with **empty SecurityContext**

What it does
- Creates `AnonymousAuthenticationToken`
- Assigns `ROLE_ANONYMOUS`

Output
- `SecurityContext.authentication = AnonymousAuthenticationToken`
🔥 This is why your login **starts as anonymous**

---

9. SessionManagementFilter

Input : Request + Authentication (anonymous or real)

What it does
- Enforces session policy:
  * Stateless
  * Max sessions
  * Session fixation protection

Output : Session validated or created (or skipped for stateless JWT)

---

10. ExceptionTranslationFilter

Input : Downstream exceptions

What it does
- Catches:
  * `AuthenticationException` → 401
  * `AccessDeniedException` → 403
- Delegates to entry points / handlers

Output
- Translates Java exceptions → HTTP responses

---

11. AuthorizationFilter (FINAL GATE)

Input : Request + Authentication + Authorization rules

What it does
- Evaluates:
  * `permitAll`
  * `hasRole`
  * `authenticated`
- Uses `AuthorizationManager`

Output
- ✅ Allowed → continue to controller
- ❌ Denied → exception → handled by ExceptionTranslationFilter