# Spring Boot Authentication & Spring Security – Learning Project
![Session Based Login flow](assets/SessionBasedSpringSecurity.png)

This repository is a **hands-on learning project** focused on understanding **authentication, authorization, and Spring Security internals** using Spring Boot.

📌 **Architecture & flow diagrams:**
👉 [https://app.eraser.io/workspace/rCDoHwxMBmptJvOQz8cg?origin=share](https://app.eraser.io/workspace/rCDoHwxMBmptJvOQz8cg?origin=share)

---

## 1. Why this project?

Most tutorials show *what to configure*, but not *what actually happens*.

This project focuses on:

* How requests flow from OS → JVM → Tomcat → Spring
* How Spring Security integrates with the servlet container
* How authentication & authorization really work internally
* How sessions, SecurityContext, filters, and roles behave at runtime

---

## 2. What happens when Spring Security is added?

When `spring-boot-starter-security` is added to `pom.xml`:

* **All endpoints become secured by default**
* Spring Security registers a **Security Filter Chain** in the servlet container
* Requests are intercepted **before reaching controllers**

Spring Security supports multiple authentication mechanisms:

* **Form Login** → browser-based clients
* **HTTP Basic** → non-browser clients (Postman, curl, services)
* (Later: JWT, OAuth2, LDAP, etc.)

---

## 3. JVM, Spring Boot, and Servlet Container startup (Production view)

In production, the application is started explicitly:

```bash
java -jar app.jar
```

### What happens step by step?

```
Linux Server
 └── JVM Process (java -jar app.jar)
      ├── Heap / Stack / Metaspace allocated
      ├── main() starts → SpringApplication.run(...)
      ├── Spring ApplicationContext created in RAM
      ├── Beans instantiated
      └── Embedded Servlet Container started (Tomcat)
           └── Binds to IP:PORT
```

The **OS maps incoming traffic** on that port to the JVM process.
Tomcat becomes the **first Java component** to receive requests.

---

## 4. Request flow: Client → Controller

```
Client (Browser / Postman)
        ↓
Servlet Container (Tomcat / Jetty)
        ↓
Spring DispatcherServlet
        ↓
@Controller / @RestController
```

Tomcat owns:

* Network sockets
* Thread pool
* Servlet execution

Spring owns:

* Controllers
* Services
* Business logic

---

## 5. How embedded Tomcat starts in Spring Boot

Spring Boot **embeds Tomcat as a library**, not as a separate process.

Spring detects a web application because the classpath contains:

* Servlet API
* Tomcat classes

Spring Boot then:

* Switches to `ServletWebServerApplicationContext`
* Creates `TomcatServletWebServerFactory`
* Programmatically builds and starts Tomcat

Conceptually:

```java
Tomcat tomcat = new Tomcat();
Connector connector = new Connector();
connector.setPort(8080);
tomcat.setConnector(connector);
tomcat.start();
```

Once started:

* Tomcat opens a TCP socket on port 8080
* OS maps IP:PORT → JVM process
* Requests flow into Tomcat

---

## 6. Tomcat dependencies inside Spring Boot

From `spring-boot-starter-web`:

```
spring-boot-starter-tomcat
 ├── tomcat-embed-core
 ├── tomcat-embed-el
 └── tomcat-embed-websocket
```

`tomcat-embed-core` contains:

* `org.apache.catalina.startup.Tomcat`
* HTTP connectors
* Thread pool
* Servlet container implementation
* Request parsing & lifecycle

---

## 7. Where do beans live? Who owns what?

| Component                     | Owned by | Stored in                 |
| ----------------------------- | -------- | ------------------------- |
| Controllers / Services        | Spring   | Spring ApplicationContext |
| DispatcherServlet             | Spring   | Spring ApplicationContext |
| TomcatServletWebServerFactory | Spring   | Spring ApplicationContext |
| Tomcat instance               | Tomcat   | JVM Heap                  |
| Servlet mappings              | Tomcat   | Tomcat Context            |
| Filters / Listeners           | Tomcat   | Tomcat Context            |

Important detail:

> **DispatcherServlet is a Spring bean, but executed by Tomcat**

```
Spring creates DispatcherServlet
        ↓
Registers it into Tomcat
        ↓
Tomcat invokes DispatcherServlet.service()
```

---

## 8. Tomcat object graph (runtime view)

An **object graph** is a set of Java objects connected via references.

```
Tomcat
 ├── Server
 │    ├── Service
 │    │    ├── Connector (port 8080)
 │    │    └── Engine
 │    │         └── Host
 │    │              └── Context
 │    │                   ├── DispatcherServlet
 │    │                   ├── Filters
 │    │                   └── Listeners
 │    └── Executor (thread pool)
```

Each box is a Java object referencing others.

---

## 9. What changes after enabling Spring Security?

### Before Spring Security

```
Tomcat → DispatcherServlet → Controller
```

### After Spring Security

```
Tomcat
 → Security Filter Chain
   → DispatcherServlet
     → Controller
```

If authentication fails:

* Request never reaches DispatcherServlet
* Response is returned from the **filter layer**

---

## 10. SecurityFilterChain basics

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .httpBasic();
    return http.build();
}
```

This registers filters like:

* `BasicAuthenticationFilter`
* `AuthorizationFilter`

---

## 11. Authentication flow (HTTP Basic)

```
Request
 ↓
BasicAuthenticationFilter
 ↓
UsernamePasswordAuthenticationToken (unauthenticated)
 ↓
AuthenticationManager
 ↓
DaoAuthenticationProvider
 ↓
Authentication (authenticated)
 ↓
SecurityContextHolder
 ↓
AuthorizationFilter
 ↓
DispatcherServlet
```

### Internals

* `BasicAuthenticationFilter` extracts `Authorization: Basic ...`
* Creates `UsernamePasswordAuthenticationToken`
* Calls `AuthenticationManager.authenticate(...)`
* `DaoAuthenticationProvider`:

  * Loads user via `UserDetailsService`
  * Compares password via `PasswordEncoder`

---

## 12. SecurityContext & ThreadLocal

Once authenticated:

```java
SecurityContext context = SecurityContextHolder.createEmptyContext();
context.setAuthentication(authentication);
SecurityContextHolder.setContext(context);
```

Stored as:

```
Thread (request thread)
 └── ThreadLocal (SecurityContextHolder)
      └── SecurityContext
           └── Authentication
```

After request completion:

* `SecurityContextPersistenceFilter` clears ThreadLocal
* Prevents memory leaks

---

## 13. JVM memory view (Security)

```
JVM Heap
├── Spring ApplicationContext (startup-time, shared)
│   ├── SecurityFilterChain
│   ├── AuthenticationManager
│   ├── AuthenticationProviders
│   ├── UserDetailsService
│   ├── PasswordEncoder
│   └── AuthorizationManager
│
└── Per Request (runtime)
    └── ThreadLocal
         └── SecurityContext
              └── Authentication
```

---

## 14. Session-based authentication (Form Login)

* Authentication stored in `HttpSession`
* Key: `SPRING_SECURITY_CONTEXT`
* Client receives `JSESSIONID`
* Browser/Postman sends cookie on each request
* SecurityContext is restored per request

---

## 15. Steps followed in this project

1. Created basic entities and CRUD APIs
2. Added Spring Security dependency
3. Implemented `CustomUserDetailsService`
4. Configured `PasswordEncoder`
5. Implemented form-based login
6. Enabled session-based authentication
7. Added role-based authorization
8. Added ownership-based authorization
9. Customized 401 / 403 responses
10. Implemented logout using Spring Security
11. Added global exception handling (controller-level)

---

## Request Lifecycle – Spring Boot + Spring Security (Complete Flow)

Legend:
- **CAPITALIZED components** are used in this project for enabling session based security
- Other components show possible alternatives supported by Spring Security

---

### End-to-End Request Flow

```text
Client (Browser / Postman / Service)
        │
        ▼
┌────────────────────────────────────────────┐
│ Embedded Tomcat (Servlet Container)         │
│ - Accepts TCP connection                   │
│ - Assigns request thread                   │
└────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────┐
│ DelegatingFilterProxy                      │
│ - Bridge between Tomcat and Spring         │
│ - Delegates to Spring Security             │
└────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│ SecurityFilterChain                                      │
│ - Ordered list of Spring Security filters                │
└──────────────────────────────────────────────────────────┘
        │
        ├──► Authentication Filters
        │
        │   ┌──────────────────────────────────────────────┐
        │   │ Authentication Filters                        │
        │   │ - BASICAUTHENTICATIONFILTER  ← USED HERE      │
        │   │ - UsernamePasswordAuthenticationFilter        │
        │   │ - BearerTokenAuthenticationFilter (JWT)       │
        │   │ - OAuth2LoginAuthenticationFilter             │
        │   │ Purpose:                                     │
        │   │ - Extract credentials from request            │
        │   │ - Create Authentication (unauthenticated)     │
        │   └──────────────────────────────────────────────┘
        │                     │
        │                     ▼
        │   ┌──────────────────────────────────────────────┐
        │   │ AuthenticationManager                         │
        │   │ - ProviderManager (default implementation)    │
        │   │ - Delegates to AuthenticationProviders        │
        │   └──────────────────────────────────────────────┘
        │                     │
        │                     ▼
        │   ┌──────────────────────────────────────────────┐
        │   │ AuthenticationProviders                       │
        │   │ - DAOAUTHENTICATIONPROVIDER  ← USED HERE      │
        │   │ - JwtAuthenticationProvider                   │
        │   │ - LdapAuthenticationProvider                  │
        │   │ - OAuth2AuthenticationProvider                │
        │   │ Purpose:                                     │
        │   │ - Validate credentials                        │
        │   └──────────────────────────────────────────────┘
        │                     │
        │                     ▼
        │   ┌──────────────────────────────────────────────┐
        │   │ UserDetailsService                            │
        │   │ - CUSTOMUSERDETAILSSERVICE  ← USED HERE       │
        │   │ - InMemoryUserDetailsManager                  │
        │   │ - JdbcUserDetailsManager                      │
        │   │ Purpose:                                     │
        │   │ - Load user details                           │
        │   └──────────────────────────────────────────────┘
        │                     │
        │                     ▼
        │   ┌──────────────────────────────────────────────┐
        │   │ PasswordEncoder                               │
        │   │ - BCRYPTPASSWORDENCODER  ← USED HERE          │
        │   │ - DelegatingPasswordEncoder                   │
        │   │ - NoOpPasswordEncoder (dev only)              │
        │   │ Purpose:                                     │
        │   │ - Compare hashed passwords                    │
        │   └──────────────────────────────────────────────┘
        │
        ├──► ❌ Authentication Failure
        │       │
        │       ▼
        │   ┌──────────────────────────────────────────────┐
        │   │ AuthenticationEntryPoint                     │
        │   │ - Returns 401 Unauthorized                    │
        │   │ - Request never reaches controller            │
        │   └──────────────────────────────────────────────┘
        │
        └──► ✅ Authentication Success
                │
                ▼
┌──────────────────────────────────────────────────────────┐
│ SecurityContextHolder (ThreadLocal)                       │
│ - Stores Authentication for current request               │
│ - Backed by HttpSession (stateful auth)                   │
└──────────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────┐
│ AuthorizationFilter                                      │
│ - Checks access rules                                    │
│ - Uses Authentication from SecurityContext                │
│                                                          │
│ Authorization styles:                                    │
│ - hasRole / hasAuthority                                 │
│ - @PreAuthorize / @PostAuthorize                          │
│ - RequestMatcher-based rules                              │
└──────────────────────────────────────────────────────────┘
                │
        ┌───────┴────────────┐
        │                    │
        ▼                    ▼
❌ Access Denied          ✅ Access Allowed
│                        │
│                        ▼
│        ┌────────────────────────────────────────┐
│        │ DispatcherServlet                       │
│        │ - Routes request to controller          │
│        └────────────────────────────────────────┘
│                        │
│                        ▼
│        ┌────────────────────────────────────────┐
│        │ @Controller / @RestController           │
│        │ - Business logic execution              │
│        └────────────────────────────────────────┘
│
▼
┌────────────────────────────────────────────────┐
│ AccessDeniedHandler                             │
│ - Returns 403 Forbidden                        │
│ - User authenticated but not authorized        │
└────────────────────────────────────────────────┘
