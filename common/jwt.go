package common

import (
	"demo/model"
	"errors"
	"fmt"
	"github.com/astaxie/beego/logs"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"log"
	"time"
)

var SecretKEY = "secret"
var DEFAULT_EXPIRE_SECONDS int = 300
var Flag = true

type Claims struct {
	UserId uint
	jwt.StandardClaims
}

type JwtPayload struct {
	Username  string `json:"Username"`
	UserID    int    `json:"UserID"`
	IssuedAt  int64  `json:"Iat"`
	ExpiresAt int64  `json:"Exp"`
}

// 创建redis客户端
func newClient() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379", // redis地址
		Password: "",               // 密码
		DB:       0,                // 使用默认数据库
	})
	return client
}

//func GetToken(user model.User) (string, error) {
//	expirationTime := time.Now().Add(7 * 24 * time.Hour) //设置过期时间：7天
//	claims := &Claims{
//		UserId: user.ID,
//		StandardClaims: jwt.StandardClaims{
//			ExpiresAt: expirationTime.Unix(),
//			IssuedAt:  time.Now().Unix(),
//			// Issuer: "oceanlearn.tech",
//			// Subject: "user token",
//		},
//	}
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//	if tokenString, err := token.SignedString(jwtKey); err != nil {
//		return "", err
//	} else {
//		return tokenString, nil
//	}
//}
//
////从tokenString中解析出相关信息
//func ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
//	claims := &Claims{}
//
//	token, err := jwt.ParseWithClaims(tokenString, claims,
//		func(token *jwt.Token) (i interface{}, err error) {
//			return jwtKey, nil
//		})
//	return token, claims, err
//}
//

var Rds = newClient()

//generate token
func GenerateToken(user model.User, expiredSeconds int) (tokenString string, err error) {
	if expiredSeconds == 0 {
		expiredSeconds = DEFAULT_EXPIRE_SECONDS
	}

	// Create the Claims
	mySigningKey := []byte(SecretKEY)
	expireAt := time.Now().Add(time.Second * time.Duration(expiredSeconds)).Unix()
	logs.Info("Token will be expired at ", time.Unix(expireAt, 0))

	//user := *loginInfo
	claims := Claims{
		user.ID,
		jwt.StandardClaims{
			Issuer:    user.StuNumber,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expireAt,
		},
	}

	// Create the token using your claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Signs the token with a secret
	tokenStr, err1 := token.SignedString(mySigningKey)
	if err1 != nil {
		return "", errors.New("error: failed to generate token")
	}
	Flag = true
	return tokenStr, nil
}

//validate token
func ValidateToken(tokenString string) (*JwtPayload, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKEY), nil
		})

	claims, ok := token.Claims.(*Claims)
	if ok && token.Valid {
		log.Println("ok && token valid")
		logs.Info("%v %v", claims.UserId, claims.StandardClaims.ExpiresAt)
		logs.Info("Token was issued at ", time.Now().Unix())
		logs.Info("Token will be expired at ", time.Unix(claims.StandardClaims.ExpiresAt, 0))

		return &JwtPayload{
			Username:  claims.StandardClaims.Issuer,
			UserID:    int(claims.UserId),
			IssuedAt:  claims.StandardClaims.IssuedAt,
			ExpiresAt: claims.StandardClaims.ExpiresAt,
		}, nil
	} else {
		fmt.Println(err)
		return nil, errors.New("error: failed to validate token")
	}
}

//更新 token
func RefreshToken(tokenString string) (newTokenString string, err error) {
	// get previous token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKEY), nil
		})

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", err
	}

	mySigningKey := []byte(SecretKEY)
	expireAt := time.Now().Add(time.Second * time.Duration(300)).Unix() //new expired
	newClaims := Claims{
		claims.UserId,
		jwt.StandardClaims{
			Issuer:    claims.StandardClaims.Issuer, //name of token issue
			IssuedAt:  time.Now().Unix(),            //time of token issue
			ExpiresAt: expireAt,                     // new expired
		},
	}

	// generate new token with new claims
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	// sign the token with a secret
	tokenStr, err := newToken.SignedString(mySigningKey)
	if err != nil {
		return "", errors.New("error: failed to generate new fresh json web token")
	}

	return tokenStr, nil
}
