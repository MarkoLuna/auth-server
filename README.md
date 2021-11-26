### OAuth Server

Basic project that creates a server for authorize and create JWT and then be able to make request securely

## Instructions
### Download deps
```bash
$ go mod download
```

### Run project 
```bash
$ go run cmd/server/main.go
```
or 
```bash
$ make run
```

### Execute unit tests
```bash
$ make test
```

### Generate a new token

```bash
$ curl --location --request POST 'localhost:9096/oauth/token' \
    --header 'Authorization: Basic YzZjZWNlNTM6ZjEwNWFmZmY=' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password=secret' \
    --data-urlencode 'username=user'
{
    "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjNmNlY2U1MyIsImV4cCI6MTYzNzk2MTMyMSwic3ViIjoiMDAwMDAwIn0.N52iowqI2ysgQiRA3zjJZDRqYC45qW1jffqOVRtqJLM7my0wPbZSmaS4lJPc5TzCwN4SYDk67ciK2YMaqRz46A",
    "refresh_token": "NGNJY2Y4YJETY2MZMY01NJDLLTK0OTETNMQ5YMJIZWJLNGY0",
    "expires_in": 120,
    "scope": "all",
    "token_type": "Bearer"
}
```

Or

```bash
$ curl -X POST 'localhost:9096/oauth/token' \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "password=secret&username=user" \
    -u c6cece53:f105afff

{
    "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjNmNlY2U1MyIsImV4cCI6MTYzNzk2MTMyMSwic3ViIjoiMDAwMDAwIn0.N52iowqI2ysgQiRA3zjJZDRqYC45qW1jffqOVRtqJLM7my0wPbZSmaS4lJPc5TzCwN4SYDk67ciK2YMaqRz46A",
    "refresh_token": "NGNJY2Y4YJETY2MZMY01NJDLLTK0OTETNMQ5YMJIZWJLNGY0",
    "expires_in": 120,
    "scope": "all",
    "token_type": "Bearer"
}
```

#### Ping to a protected endpoint
```bash
$ curl -X GET 'http://localhost:9096/protected' \
    -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjNmNlY2U1MyIsImV4cCI6MTYzNzk2MTMyMSwic3ViIjoiMDAwMDAwIn0.N52iowqI2ysgQiRA3zjJZDRqYC45qW1jffqOVRtqJLM7my0wPbZSmaS4lJPc5TzCwN4SYDk67ciK2YMaqRz46A'
Hello, I'm protected
```

#### Get user claims
```bash
$ curl -X GET 'http://localhost:9096/getClaims' \
    -X 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjNmNlY2U1MyIsImV4cCI6MTYzNzk2MTMyMSwic3ViIjoiMDAwMDAwIn0.N52iowqI2ysgQiRA3zjJZDRqYC45qW1jffqOVRtqJLM7my0wPbZSmaS4lJPc5TzCwN4SYDk67ciK2YMaqRz46A'
{
    "audience": "c6cece53",
    "id": "",
    "issuer": "",
    "subject": "000000"
}

```
