package awesome_jwt

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"strings"
)

var (
	SigningMethodES256 = jwt.SigningMethodES256
	SigningMethodES384 = jwt.SigningMethodES384
	SigningMethodES512 = jwt.SigningMethodES512

	SigningMethodRS256 = jwt.SigningMethodRS256
	SigningMethodRS384 = jwt.SigningMethodRS384
	SigningMethodRS512 = jwt.SigningMethodRS512

	SigningMethodHS256 = jwt.SigningMethodHS256
	SigningMethodHS384 = jwt.SigningMethodHS384
	SigningMethodHS512 = jwt.SigningMethodHS512

	SigningMethodPS256 = jwt.SigningMethodPS256
	SigningMethodPS384 = jwt.SigningMethodPS384
	SigningMethodPS512 = jwt.SigningMethodPS512
)

type Generator struct {
	t   *jwt.Token
	key interface{}
	iss string
}

type GeneratorOption func(generator *Generator) *Generator

func GeneratorOptionWithKey(key interface{}, method jwt.SigningMethod) GeneratorOption {
	return func(generator *Generator) *Generator {
		generator.key = key
		generator.t = jwt.New(method)
		return generator
	}
}

// GeneratorOptionWithKeyId 一般用于非对称加密，jwk 中不能缺少 alg
func GeneratorOptionWithKeyId(kid, iss string, key interface{}) GeneratorOption {
	// 检查验证key的 kid 是否存在
	if iss == "" {
		return nil
	}
	if !strings.HasSuffix(iss, "/") {
		iss = iss + "/"
	}
	path := iss + JWKsRelativePath
	_, k, err := ParsePathToKey(path, kid)
	if err != nil {
		return nil
	}

	return func(generator *Generator) *Generator {
		generator.key = key // 签名 key
		generator.t = jwt.New(jwt.GetSigningMethod(k.Alg))
		generator.t.Header["kid"] = kid
		generator.iss = iss
		return generator
	}
}

func NewGenerator(options ...GeneratorOption) *Generator {
	g := &Generator{}
	for _, option := range options {
		g = option(g)
	}
	return g
}

func (g *Generator) Sign(claims jwt.Claims) (string, error) {
	g.t.Claims = claims
	if g.iss != "" {
		switch claims.(type) {
		case jwt.MapClaims:
			c := claims.(jwt.MapClaims)
			c["iss"] = g.iss
			g.t.Claims = c
		case jwt.StandardClaims:
			c := claims.(jwt.StandardClaims)
			c.Issuer = g.iss
			g.t.Claims = c
		default:
			return "", errors.New("cannot support your own claims")
		}
	}
	return g.t.SignedString(g.key)
}

func (g *Generator) GetSigning(claims jwt.Claims) (string, error) {
	g.t.Claims = claims
	if g.iss != "" {
		switch claims.(type) {
		case jwt.MapClaims:
			c := claims.(jwt.MapClaims)
			c["iss"] = g.iss
			g.t.Claims = c
		case jwt.StandardClaims:
			c := claims.(jwt.StandardClaims)
			c.Issuer = g.iss
			g.t.Claims = c
		default:
			return "", errors.New("cannot support your own claims")
		}
	}
	return g.t.SigningString()
}
