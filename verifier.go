package awesome_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"reflect"
	"strings"
)

const (
	JWKsRelativePath = ".well-known/jwks.json"
)

type Claims interface {
	Valid() error
	VerifyAudience(cmp string, req bool) bool
	VerifyExpiresAt(cmp int64, req bool) bool
	VerifyIssuedAt(cmp int64, req bool) bool
	VerifyIssuer(cmp string, req bool) bool
	VerifyNotBefore(cmp int64, req bool) bool
}

type Verifier struct {
	p                   *jwt.Parser
	defaultKey          interface{}
	skipClaimVerify     bool
	useJSONNumber       bool
	validSigningMethods []string
	useClaims           jwt.Claims // 验证时使用的 claims，可使用 struct 来限制 jwt 的格式
	verifyAud           string     // 验证 Aud	仅当 skipClaimVerify = false 才启用
	verifyIss           string     // 验证 Iss   仅当 skipClaimVerify = false 才启用
}

type VerifierOption func(verifier *Verifier) *Verifier

var (
	SkipClaimVerifyOption     VerifierOption // 不去验证 Claims 的正确性，即不验证 jwt 是否过期或者是否启用
	UseJSONNumberVerifyOption VerifierOption // 使用 JSON number decoder

	UseMapClaimsOption VerifierOption // 使用 MapClaims 来解析(默认情况下不限制)

	AcceptNoneSigningOption VerifierOption // 使用这个 Option 后，当 jwt 当 alg 为 none 且使用 VerifyWithDefaultKey 时才有效(认证通过)，但不推荐使用
)

func VerifyAudOption(aud string) VerifierOption {
	return func(verifier *Verifier) *Verifier {
		verifier.verifyAud = aud
		return verifier
	}
}

// VerifyDefaultKeyOption 使用 AcceptNoneSigningOption 后不能使用这个
func VerifyDefaultKeyOption(key interface{}) VerifierOption {
	return func(verifier *Verifier) *Verifier {
		verifier.defaultKey = key
		return verifier
	}
}

func VerifyIssOption(iss string) VerifierOption {
	return func(verifier *Verifier) *Verifier {
		verifier.verifyIss = iss
		return verifier
	}
}

func AdmitMethodsVerifyOption(methods ...jwt.SigningMethod) VerifierOption {
	algs := make([]string, len(methods))
	for i, method := range methods {
		algs[i] = method.Alg()
	}
	return func(verifier *Verifier) *Verifier {
		verifier.validSigningMethods = algs
		return verifier
	}
}

func UseStructClaimsOption(claims jwt.Claims) VerifierOption {
	if reflect.TypeOf(claims) == reflect.TypeOf(jwt.MapClaims{}) {
		return func(verifier *Verifier) *Verifier {
			return verifier // do nothing
		}
	}
	return func(verifier *Verifier) *Verifier {
		verifier.useClaims = claims
		return verifier
	}
}

func init() {
	SkipClaimVerifyOption = func(verifier *Verifier) *Verifier {
		verifier.skipClaimVerify = true
		return verifier
	}

	UseJSONNumberVerifyOption = func(verifier *Verifier) *Verifier {
		verifier.useJSONNumber = true
		return verifier
	}

	UseMapClaimsOption = func(verifier *Verifier) *Verifier {
		verifier.useClaims = jwt.MapClaims{}
		return verifier
	}

	AcceptNoneSigningOption = func(verifier *Verifier) *Verifier {
		verifier.defaultKey = jwt.UnsafeAllowNoneSignatureType
		return verifier
	}
}

func NewVerifier(options ...VerifierOption) *Verifier {
	v := &Verifier{}
	for _, option := range options {
		v = option(v)
	}
	initVerifier(v)
	return v
}

func initVerifier(verifier *Verifier) {
	verifier.p = &jwt.Parser{
		ValidMethods:         verifier.validSigningMethods,
		UseJSONNumber:        verifier.useJSONNumber,
		SkipClaimsValidation: verifier.skipClaimVerify,
	}

	if verifier.useClaims == nil {
		verifier.useClaims = jwt.MapClaims{}
	}
}

func (v *Verifier) verifyTokenStr(jwtStr string) (*jwt.Token, []string, error) {
	token, parts, err := v.p.ParseUnverified(jwtStr, v.useClaims)
	// Verify signing method is in the required set
	if v.validSigningMethods != nil {
		var signingMethodValid = false
		var alg = token.Method.Alg()
		for _, m := range v.validSigningMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return token, parts, errors.New(fmt.Sprintf("signing method %v is invalid", alg))
		}
	}

	// Validate Claims
	if !v.skipClaimVerify {
		if err = token.Claims.Valid(); err != nil {
			return token, parts, err
		}
		claims, ok := token.Claims.(Claims)
		if !ok {
			return token, parts, errors.New("do not recommend you to design your own Claims, if you want, implement awesome_jwt.Claims instead")
		}
		if v.verifyAud != "" {
			if claims.VerifyAudience(v.verifyAud, true) == false {
				return token, parts, errors.New(fmt.Sprintf("aud verified failed, expect %v", v.verifyAud))
			}
		}

		if v.verifyIss != "" {
			if claims.VerifyIssuer(v.verifyIss, true) == false {
				return token, parts, errors.New(fmt.Sprintf("iss verified failed, expect %v", v.verifyIss))
			}
		}
	}

	return token, parts, nil
}

func (v *Verifier) Verify(jwtStr string, key interface{}) error {
	token, parts, err := v.verifyTokenStr(jwtStr)
	if err != nil {
		return err
	}

	// 防止这里使用 jwt.UnsafeAllowNoneSignatureType
	if _, ok := key.(string); ok {
		return errors.New("key cannot be string")
	}
	return token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
}

func (v *Verifier) VerifyWithDefaultKey(jwtStr string) error {
	if v.defaultKey == nil {
		return errors.New("no default key")
	}
	token, parts, err := v.verifyTokenStr(jwtStr)
	if err != nil {
		return err
	}
	return token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], v.defaultKey)
}

func (v *Verifier) VerifyWithKid(jwtStr string) error {
	token, parts, err := v.verifyTokenStr(jwtStr)
	if err != nil {
		return err
	}
	var kid interface{}
	var ok bool
	if kid, ok = token.Header["kid"]; !ok {
		return errors.New("cannot find kid in jwt header")
	}
	keyId, ok := kid.(string)
	if !ok {
		return errors.New("kid cannot cast to string")
	}
	var iss string
	if c, ok := token.Claims.(jwt.MapClaims); ok {
		iss, ok = c["iss"].(string)
		if !ok {
			return errors.New("iss cannot cast to string")
		}
	} else {
		claims := token.Claims.(jwt.StandardClaims)
		iss = claims.Issuer
	}

	if iss == "" {
		return errors.New("iss cannot be empty")
	}

	if !strings.HasSuffix(iss, "/") {
		iss = iss + "/"
	}

	path := iss + JWKsRelativePath

	publicKey, _, err := ParsePathToKey(path, keyId)

	if err != nil {
		return err
	}

	return token.Method.Verify(strings.Join(parts[0:2], "."), parts[2], publicKey)
}
