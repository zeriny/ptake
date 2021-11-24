

- checkcname 会检查CNAME域名是否可注册（available）

- full 会检查完整的DNS解析链（无论中间域名是否已被检查为Vulnerable）

## Input Format


## Configuration



## Compile
```
$ env GOOS=linux GOARCH=amd64 go build -o ./bin/ptake_amd64 main.go
$ env GOOS=linux GOARCH=arm64 go build -o ./bin/ptake_arm64 main.go
```