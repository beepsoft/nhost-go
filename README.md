# Nhost golang client SDK - WIP

This is a port of the [Nhost JavaScript SDK](https://github.com/nhost/nhost/tree/main/packages/nhost-js) to golang. The plan is to provide the same functionality as the JS SDK but for projects using golang.

Basic usage:

```go
package main

import (
  "fmt"
  "github.com/beepshow/nhost-go/hasura_auth"
  "github.com/beepshow/nhost-go/nhost"
)

func main() { 
  // Assume nhost running locally. For remote specify the correct subdomain and region. 
  nhostClient, err := nhost.New("localhost", "")
  if err != nil {
    panic(err)
  }

  // Auth token will be updated
  nhostClient.Auth.OnTokenChanged(func(session *hasura_auth.Session) {
    if session == nil {
      fmt.Printf("Session ended\n")
    } else {
      fmt.Printf("Updated access token: %s\n", session.AccessToken)
    }
  })

  // Force token refresh every 5 seconds
  nhostClient.Auth.RefreshIntervalTime = 5

  // Sign in nhost user foo@bar.com
  signInRes := nhostClient.Auth.SignInEmailPassword(hasura_auth.SignInEmailPasswordParams{
    Email:    "foo@bar.com",
    Password: "s3cr3t",
  })
  if signInRes.Error != nil {
    panic(signInRes.Error.Message)
  }

  // Just keep running to have the token change function called
  select {}
}

```

Implemented features:
- NhostClient providing access to Auth, Storage (and later Graphql and Functions) clients
- Auth client
  - Sign in with email/password (`nhostClient.Auth.SignInEmailPassword()`)
  - Sign out (`nhostClient.Auth.SignOut()`
  - Callbacks on token change (`nhostClient.Auth.OnTokenChanged()`) and auth status change (`nhostClientAuth.OnAuthStateChanged()`)
- Storage client
  - Automatic update of access token when Auth refreshes token
  - Get presigned URL for downloading files (nhostClient.Storage.GetPresignedUrl())
