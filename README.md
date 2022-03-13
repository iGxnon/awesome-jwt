# Awesome-jwt

> 自用的 jwt 二次封装库
> 
> 使用了如下的基础库

+ github.com/dgrijalva/jwt-go
+ github.com/mendsley/gojwk

> 使用 Builder 模式抽象出 generator 和 verifier 来进行 `签名` 与 `认证`


+ 支持从 `iss/.well-known/jwks.json` 内读取非对称加密的 public key 来认证

+ 预计支持 jwe 格式的 jwt