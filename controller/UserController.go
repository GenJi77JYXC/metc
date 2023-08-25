package controller

import (
	"demo/common"
	"demo/model"
	"demo/response"
	"demo/util"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}

var Token_logout string

func Register(ctx *gin.Context) {
	db := common.GetDB()
	//获取参数
	stuNumber := ctx.PostForm("stuNumber")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")
	//数据验证
	if len(stuNumber) != 10 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": stuNumber}, "学号必须10位")
		return
	}
	if !VerifyEmailFormat(email) {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": email}, "邮箱格式不正确")
		return
	}
	if len(password) < 8 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": password}, "密码必须大于8位")
		return
	}
	log.Println(stuNumber, email, password)

	//判断邮箱是否存在
	if isEmailExist(db, email) {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": email}, "邮箱已注册")
		return
	}

	//创建用户
	hashdPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) //密码hash化
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, gin.H{"msg": "加密错误"}, "加密错误")
		return
	}
	newUser := model.User{
		StuNumber: stuNumber,
		Email:     email,
		Password:  string(hashdPassword),
	}
	if err := db.Create(&newUser).Error; err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": "建表错误"}, err.Error())
		return
	}

	response.Success(ctx, gin.H{"msg": "注册成功"}, "注册成功")

}

func isEmailExist(db *gorm.DB, telephone string) bool {
	var user model.User
	db.Where("email=?", telephone).First(&user)
	return user.ID != 0
}

func Login(ctx *gin.Context) {
	db := common.GetDB()
	//获取参数
	stuNumber := ctx.PostForm("stunumber")
	password := ctx.PostForm("password")

	//数据校验
	if len(stuNumber) != 10 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": stuNumber}, "学号必须10位")
		return
	}
	if len(password) < 8 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": password}, "密码必须大于8位")
		return
	}

	//判断学号是否存在
	var user model.User
	db.Where("stu_number=?", stuNumber).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": stuNumber}, "学号不存在")
		return
	}

	//判断密码是否正确
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 400, gin.H{"msg": password}, "密码错误")
		return
	}

	//发送token
	//token, err := common.GetToken(user)
	token, err := common.GenerateToken(user, 0)
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, gin.H{"msg": "系统token获取异常"}, "系统token获取异常")
		return
	}

	err2 := common.Rds.Set("token", token, 300*time.Second).Err()
	if err2 != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, gin.H{"msg": "系统token获取异常"}, "token存入redis错误")
		return

	}

	response.Success(ctx, gin.H{"token": token}, "登录成功")

}

func UserInfo(ctx *gin.Context) {
	user, _ := ctx.Get("user")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}
	response.Success(ctx, gin.H{"user": user}, "信息列表")
}

func UploadInfo(ctx *gin.Context) {
	db := common.GetDB()
	// 获取参数
	UserStuNumber := ctx.PostForm("stunumber")
	Email := ctx.PostForm("email")
	Name := ctx.PostForm("name")
	Profession := ctx.PostForm("profession")
	Academy := ctx.PostForm("academy")
	Hobby := ctx.PostForm("hobby")
	Intro := ctx.PostForm("intro")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}

	var user model.User
	//db.Table("users").Where("stu_number=?", UserStuNumber).First(&user)
	db.Where("stu_number=?", UserStuNumber).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": UserStuNumber}, "学号不存在")
		return
	}

	tokenString := ctx.GetHeader("Authorization")
	tokenString = tokenString[7:] //token的前面是“bearer”，有效部分从第7位开始
	//从tokenString中解析信息
	JwtPayload, err := common.ValidateToken(tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"})
		ctx.Abort()
		return
	}
	// 验证tokenString中的user信息与输入的学号是否一致
	if JwtPayload.Username != UserStuNumber {
		ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "当前账号与需要提交的学号不一致，请重新输入"})
	}

	var userDto model.UserDto
	db.Table("user_dtos").Where("user_stu_number=?", UserStuNumber).First(&userDto)
	if userDto.ID != 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, gin.H{"msg": UserStuNumber}, "已经提交过了，请勿重复提交")
		return
	}
	Userdto := model.UserDto{
		UserStuNumber: UserStuNumber,
		Email:         Email,
		Name:          Name,
		Profession:    Profession,
		Academy:       Academy,
		Hobby:         Hobby,
		Intro:         Intro,
	}
	if err := db.Create(&Userdto).Error; err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": "信息保存出错"}, err.Error())
		return
	}

	response.Success(ctx, gin.H{"data": Userdto}, "提交成功")
}

//email格式验证
func VerifyEmailFormat(email string) bool {
	//pattern := `\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*` //匹配电子邮箱
	pattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`

	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

func SendRegVerifyMail(ctx *gin.Context) {
	db := common.GetDB()
	//获取参数
	stuNumber := ctx.PostForm("stunumber")
	email := ctx.PostForm("email")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}

	//数据校验
	if len(stuNumber) != 10 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": stuNumber}, "学号必须10位")
		return
	}
	if !VerifyEmailFormat(email) {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": email}, "邮箱格式不正确")
		return
	}

	//判断学号是否存在
	var user model.User
	db.Where("stu_number=?", stuNumber).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": stuNumber}, "学号不存在")
		return
	}
	//判断学号对应的邮箱是否是输入的邮箱
	if user.Email != email {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": email}, "学号对应的邮箱不正确")
		return
	}
	//生成随机6位数，并发送
	code := rand.Intn(899999) + 100000
	s := strconv.Itoa(code)
	user.Code = s
	db.Save(&user)
	util.VerifyEmail("genji77@qq.com", user.Email, s)
	response.Success(ctx, gin.H{"msg": "验证码发送成功"}, "验证码发送成功")
}

func ChangePasswordByemail(ctx *gin.Context) {
	db := common.GetDB()
	//获取参数
	stuNumber := ctx.PostForm("stunumber")
	verifyCode := ctx.PostForm("code")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}
	var user model.User
	db.Where("stu_number=?", stuNumber).First(&user)
	if !ConfirmVerifyCode(user, verifyCode) {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": verifyCode}, "验证码不正确")
		return
	}
	password := ctx.PostForm("password")
	if len(password) < 8 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": password}, "密码必须大于8位")
		return
	}
	hashdPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) //密码hash化
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, gin.H{"msg": "加密错误"}, "加密错误")
		return
	}
	user.Password = string(hashdPassword)
	db.Save(&user)
	response.Success(ctx, gin.H{"msg": "密码修改成功"}, "密码修改成功")
}

func ConfirmVerifyCode(user model.User, verifyCode string) bool {
	return user.Code == verifyCode

}

func Logout(ctx *gin.Context) {
	tokenString := ctx.GetHeader("Authorization")
	//fmt.Println(tokenString + "------   token")
	tokenString = tokenString[7:] //前面的bearer不要
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}
	Token_logout = randomString(20)
	err := common.Rds.Set(Token_logout, tokenString, 300*time.Second).Err()

	if err != nil {
		response.Fail(ctx, gin.H{"msg": "登出失败"}, "redis中存入token错误")
		return
	}

	//if err != nil {
	//	response.Fail(ctx, gin.H{"msg": "登出失败"}, "token解析错误")
	//	return
	//}

	response.Success(ctx, gin.H{"msg": "登出成功"}, "登出成功")
}
func CheckInfo(ctx *gin.Context) {
	user, _ := ctx.Get("user")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}
	response.Success(ctx, gin.H{"user": user}, "查看信息")
}

func ChangeInfo(ctx *gin.Context) {
	db := common.GetDB()
	// 获取参数
	UserStuNumber := ctx.PostForm("stunumber")
	Email := ctx.PostForm("email")
	Name := ctx.PostForm("name")
	Profession := ctx.PostForm("profession")
	Academy := ctx.PostForm("academy")
	Hobby := ctx.PostForm("hobby")
	Intro := ctx.PostForm("intro")
	if common.Flag == false {
		response.Fail(ctx, gin.H{"code": 401}, "登录验证过期")
		return
	}

	tokenString := ctx.GetHeader("Authorization")
	tokenString = tokenString[7:] //token的前面是“bearer”，有效部分从第7位开始
	//从tokenString中解析信息
	JwtPayload, err := common.ValidateToken(tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "登录验证过期，请重新登陆"})
		ctx.Abort()
		return
	}
	// 验证tokenString中的user信息与输入的学号是否一致
	if JwtPayload.Username != UserStuNumber {
		ctx.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "当前账号与需要修改的学号不一致，请重新输入"})
	}
	//fmt.Println(UserStuNumber + "输入的学号")
	//fmt.Println(JwtPayload.Username + "当前账号学号JwtPayload的name")

	var user model.User
	//db.Table("users").Where("stu_number=?", UserStuNumber).First(&user)
	db.Where("stu_number=?", UserStuNumber).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 442, gin.H{"msg": UserStuNumber}, "学号不存在")
		return
	}
	var userDto model.UserDto
	db.Table("user_dtos").Where("user_stu_number=?", UserStuNumber).First(&userDto)
	if userDto.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, gin.H{"msg": "您还未提交过信息，请先提交一次再修改！"}, "您还未提交过信息，请先提交一次再修改！")
		return
	}
	userDto.Email = Email
	userDto.Name = Name
	userDto.Profession = Profession
	userDto.Academy = Academy
	userDto.Hobby = Hobby
	userDto.Intro = Intro

	db.Save(&userDto)
	response.Success(ctx, gin.H{"msg": UserStuNumber}, "修改成功")
}

func Index(ctx *gin.Context) {
	response.Success(ctx, gin.H{"msg": "了解社团"}, "了解社团")
}

func About(ctx *gin.Context) {
	response.Success(ctx, gin.H{"msg": "联系方式"}, "邮箱号，QQ号，qq群的二维码")
}

func GetMore(ctx *gin.Context) {
	response.Success(ctx, gin.H{"msg": "获取资源"}, "获取学习资源")
}
