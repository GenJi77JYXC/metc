package util

import (
	"github.com/jordan-wright/email"
	"github.com/spf13/viper"
	"log"
	"net/smtp"
	"os"
)

func InitConfig() {
	workDir, _ := os.Getwd() //获取当前目录
	viper.SetConfigName("application")
	viper.SetConfigType("yml")
	viper.AddConfigPath(workDir + "/config")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}

func VerifyEmail(fromEmail, toEmail, code string) {
	e := email.NewEmail()
	e.From = fromEmail
	e.To = []string{toEmail}
	e.Subject = "metc用户密码找回"
	e.Text = []byte("你的验证码是" + code)
	err := e.Send("smtp.qq.com:25", smtp.PlainAuth("", fromEmail, "idvzfexmcjyvccce", "smtp.qq.com"))
	if err != nil {
		log.Fatal(err)
	}
}
