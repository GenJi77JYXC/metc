package main

import (
	"demo/common"
	"demo/route"
	"demo/util"
	"github.com/jinzhu/gorm"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func main() {
	util.InitConfig()
	db := common.GetDB()

	defer func(db *gorm.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	var r *gin.Engine = gin.Default()
	r = route.CollectRoute(r)

	port := viper.GetString("server.port")
	if port != "" {
		panic(r.Run(":" + port))
	}
	panic(r.Run())

}
