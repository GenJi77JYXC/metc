package model

import "github.com/jinzhu/gorm"

type User struct {
	gorm.Model
	StuNumber string `gorm:"not null;unique"`
	Email     string `gorm:"not null;unique"`
	Password  string `gorm:"size(255);not null"`
	Code      string
	UserDto   UserDto `gorm:"ForeignKey:UserDtoID;AssociationForeignKey:UserStuNumber"`
	UserDtoID int
}

type UserDto struct {
	gorm.Model
	UserStuNumber string `json:"学号"`
	Email         string `json:"邮箱"`
	Name          string `json:"姓名"`
	Academy       string `json:"学院"`
	Profession    string `json:"专业"`
	Hobby         string `json:"兴趣方向"`
	Intro         string `json:"自我介绍"`
}

func ToUserDto(user *User) UserDto {
	return UserDto{
		UserStuNumber: user.StuNumber,
		Email:         user.Email,
	}
}
