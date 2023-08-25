package route

import (
	"demo/controller"
	"demo/middleware"

	"github.com/gin-gonic/gin"
)

func CollectRoute(r *gin.Engine) *gin.Engine {
	r.POST("api/auth/register", controller.Register)
	r.POST("api/auth/login", controller.Login)
	r.GET("api/auth/login/info", middleware.AuthMiddleware(), controller.UserInfo)
	r.POST("api/auth/forgotpassword", controller.SendRegVerifyMail)
	r.POST("api/auth/changepassword", controller.ChangePasswordByemail)
	r.POST("api/auth/logout", middleware.AuthMiddleware(), controller.Logout)
	r.POST("api/auth/index", middleware.AuthMiddleware(), controller.CheckInfo)
	r.POST("api/auth/uploadinfo", middleware.AuthMiddleware(), controller.UploadInfo)
	r.PUT("api/auth/changeindex", middleware.AuthMiddleware_UpdateInfo(), controller.ChangeInfo)
	r.GET("api/index", controller.Index)
	r.GET("api/about", controller.About)
	r.GET("api/getmore", controller.GetMore)
	return r
}
