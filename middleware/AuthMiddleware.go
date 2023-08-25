package middleware

import (
	"demo/common"
	"demo/controller"
	"demo/model"
	"demo/respon"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

//验证解析token
func AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		//获取authorization header
		tokenString := ctx.GetHeader("Authorization")

		//验证token格式,若token为空或不是以Bearer开头，则token格式不对
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "token错误"})
			ctx.Abort() //将此次请求抛弃
			return
		}

		tokenString = tokenString[7:] //token的前面是“bearer”，有效部分从第7位开始

		_, errM := common.Rds.Get("nothing").Result()
		blackToken, err1 := common.Rds.Get(controller.Token_logout).Result()
		if blackToken == tokenString {
			respon.Fail(ctx, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"}, "用户已登出")
			common.Flag = false
			return
		}
		if err1 != nil && err1 != errM {
			respon.Fail(ctx, gin.H{"msg": "redis获取token错误"}, "redis获取token错误")
		}

		//从tokenString中解析信息
		//token, claims, err := common.ParseToken(tokenString)
		JwtPayload, err := common.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"})
			ctx.Abort()
			return
		}

		// 查询tokenString中的user信息是否存在
		userId := JwtPayload.UserID
		db := common.GetDB()
		var user model.User
		db.First(&user, userId)

		if user.ID == 0 {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "权限不足"})
			ctx.Abort()
			return
		}

		//若存在该用户则将用户信息写入上下文
		userDto := model.ToUserDto(&user)
		ctx.Set("user", userDto)
		ctx.Next()
	}
}

func AuthMiddleware_UpdateInfo() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		//获取authorization header
		tokenString := ctx.GetHeader("Authorization")

		//验证token格式,若token为空或不是以Bearer开头，则token格式不对
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer") {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "token错误"})
			ctx.Abort() //将此次请求抛弃
			return
		}

		tokenString = tokenString[7:] //token的前面是“bearer”，有效部分从第7位开始
		_, errM := common.Rds.Get("nothing").Result()
		blackToken, err1 := common.Rds.Get(controller.Token_logout).Result()
		if blackToken == tokenString {
			respon.Fail(ctx, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"}, "用户已登出")
			common.Flag = false
			return
		}
		if err1 != nil && err1 != errM {
			respon.Fail(ctx, gin.H{"msg": "redis获取token错误"}, "redis获取token错误")
		}

		//从tokenString中解析信息
		//token, claims, err := common.ParseToken(tokenString)
		JwtPayload, err := common.ValidateToken(tokenString)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"})
			ctx.Abort()
			return
		}

		// 查询tokenString中的user信息是否存在
		userId := JwtPayload.UserID
		db := common.GetDB()
		var user model.User
		db.First(&user, userId)

		if user.ID == 0 {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "用户信息不存在"})
			ctx.Abort()
			return
		}
		if user.StuNumber != JwtPayload.Username {
			ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "当前账号与需要修改的学号不一致，请重新输入"})
			ctx.Abort()
			return
		}

		//若存在该用户则将用户信息写入上下文
		userDto := model.ToUserDto(&user)
		ctx.Set("user", userDto)
		ctx.Next()
	}
}
