# AuthzX Go SDK

Go client for [AuthzX](https://authzx.com) — works with both AuthzX Cloud and the local AuthzX Agent.

## Install

```bash
go get github.com/authzx/authzx-go
```

## Usage

### Cloud Mode

```go
package main

import (
    "context"
    "fmt"
    authzx "github.com/authzx/authzx-go"
)

func main() {
    client := authzx.NewClient("azx_...")

    allowed, err := client.Check(context.Background(),
        authzx.Subject{ID: "user:123", Type: "user", Roles: []string{"editor"}},
        "read",
        authzx.Resource{Type: "document", ID: "doc:456"},
    )
    if err != nil {
        panic(err)
    }
    fmt.Println("Allowed:", allowed)
}
```

### Agent Mode (local)

```go
client := authzx.NewClient("", authzx.WithBaseURL("http://localhost:8181"))
```

### Full Authorize Response

```go
resp, err := client.Authorize(ctx, &authzx.AuthorizeRequest{
    Subject:  authzx.Subject{ID: "user:123", Type: "user"},
    Resource: authzx.Resource{Type: "document", ID: "doc:456"},
    Action:   "read",
    Context:  map[string]interface{}{"ip": "10.0.0.1"},
})
// resp.Allowed, resp.Reason, resp.PolicyID, resp.AccessPath
```

### net/http Middleware

```go
mux := http.NewServeMux()
mux.Handle("/documents/", client.HTTPMiddleware("document", "read", "X-User-ID")(handler))
```

### Gin Middleware

```go
func AuthzMiddleware(client *authzx.Client, resourceType, action string) gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed, err := client.Check(c.Request.Context(),
            authzx.Subject{ID: c.GetHeader("X-User-ID"), Type: "user"},
            action,
            authzx.Resource{Type: resourceType, ID: c.Param("id")},
        )
        if err != nil || !allowed {
            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
            return
        }
        c.Next()
    }
}

router.GET("/documents/:id", AuthzMiddleware(client, "document", "read"), handler)
```

### Options

```go
authzx.NewClient(apiKey,
    authzx.WithBaseURL("http://localhost:8181"),  // Custom URL
    authzx.WithHTTPClient(customHTTPClient),       // Custom http.Client
    authzx.WithTimeout(5 * time.Second),           // Custom timeout
)
```

## Types

| Type | Fields |
|------|--------|
| `Subject` | `ID`, `Type`, `Attributes`, `Roles` |
| `Resource` | `Type`, `ID`, `Attributes` |
| `AuthorizeRequest` | `Subject`, `Resource`, `Action`, `Context` |
| `AuthorizeResponse` | `Allowed`, `Reason`, `PolicyID`, `AccessPath` |
