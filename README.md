### OAuth Server





## Instructions
```bash
$ go mod download
```

```bash
$ go run cmd/server/main.go
```

```bash
$ curl -X GET 'http://localhost:9096/credentials'
{
    "CLIENT_ID": "b607e0d3",
    "CLIENT_SECRET": "8f1755fd"
}

$ curl -X GET 'http://localhost:9096/token?grant_type=client_credentials&client_id=b607e0d3&client_secret=8f1755fd&scope=all'
{
    "access_token": "BLTCJ6GNPEKEOQ8VYA3DVG",
    "expires_in": 7200,
    "scope": "all",
    "token_type": "Bearer"
}

$ curl -X GET 'http://localhost:9096/protected?access_token=BLTCJ6GNPEKEOQ8VYA3DVG'

# Or
$ curl -X GET 'http://localhost:9096/protected' -H 'Authorization: Bearer BLTCJ6GNPEKEOQ8VYA3DVG'

```
