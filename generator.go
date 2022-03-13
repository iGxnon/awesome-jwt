package awesome_jwt

import (
	"github.com/dgrijalva/jwt-go"
)

type Generator struct {
	t *jwt.Token
}

func NewGenerator() *Generator {
	g := &Generator{}
	return g
}

func (g *Generator) Sign(key interface{}) (string, error) {
	return g.t.SignedString(key)
}
