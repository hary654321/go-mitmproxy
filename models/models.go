package models

import (
	"fmt"
	"log"
	"strings"

	"github.com/lqqyt2423/go-mitmproxy/config"
	"gorm.io/gorm/logger"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

type Model struct {
	ID int `gorm:"primary_key" json:"id"`
}

func Setup() {
	var err error

	log.Println("db配置", config.Gc.Database.Mysql)
	db, err = gorm.Open(mysql.Open(config.Gc.Database.Mysql), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		log.Println("models.Setup err: %v", err)
	}

	// gorm.DefaultTableNameHandler = func(db *gorm.DB, defaultTableName string) string {
	// 	return config.CoreConf.Server.DB.TablePrefix + "_" + defaultTableName
	// }

}

func getInWhere(conds []string) string {

	ss := strings.Join(conds, "','")
	res := fmt.Sprintf("(%s)", ss)

	println(res)
	return res
}
