package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type ConfigureInterface interface {
	GetAppConfig() App
	GetDatabaseConfig() Database
	GetTaskConfig() Task
	GetLogConfig() Log
}

var _ ConfigureInterface = (*GlobalCopnfig)(nil)

type GlobalCopnfig struct {
	App      App      `json:"app"`
	Database Database `json:"database"`
	Task     Task     `json:"task"`
	Log      Log      `json:"log"`
}

type App struct {
	Role      string `json:"role"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Templates string `json:"templates"`
	Scanner   string `json:"scanner"`
}

type Database struct {
	Mysql         string `json:"mysql"`
	Elasticsearch string `json:"elasticsearch"`
}

type Task struct {
	DataDir    string `json:"data_dir"`
	MaxTaskNum int    `json:"max_task_num"`
}

type Log struct {
	FileName     string `json:"file_name"`
	Level        string `json:"level"`
	DataDir      string `json:"data_dir"`
	MaxAge       int    `json:"max_age"`
	MaxSize      int    `json:"max_size"`
	MaxBackups   int    `json:"max_backups"`
	Compress     bool   `json:"compress"`
	JsonFormat   bool   `json:"json_format"`
	ShowLine     bool   `json:"show_line"`
	LogInConsole bool   `json:"log_in_console"`
}

var Gc GlobalCopnfig

func NewConfig(path string) *GlobalCopnfig {
	v := viper.New()

	v.SetConfigName("config")

	v.SetConfigType("yaml")

	v.AddConfigPath(".")

	// 可选：设置默认配置值，以备配置文件中缺少某些配置项时使用
	v.SetDefault("app.role", "slave")
	v.SetDefault("app.address", "localhost")
	v.SetDefault("app.port", 18080)

	v.SetDefault("database.mysql", "localhost")
	v.SetDefault("database.elasticsearch", 3306)

	v.SetDefault("task.data_dir", "TASK_DATA_DIR")
	v.SetDefault("task.max_task_num", 10)

	v.SetDefault("log.file_name", "webscan.log")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.data_dir", "LOG_DATA_DIR")
	v.SetDefault("log.max_age", 7)
	v.SetDefault("log.max_size", 100)
	v.SetDefault("log.max_backups", 10)
	v.SetDefault("log.compress", true)
	v.SetDefault("log.json_format", true)
	v.SetDefault("log.show_line", true)
	v.SetDefault("log.log_in_console", true)

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		panic(err)
	}

	app := App{
		Role:      v.GetString("app.role"),
		Address:   v.GetString("app.address"),
		Port:      v.GetInt("app.port"),
		Templates: v.GetString("app.templates"),
		Scanner:   v.GetString("app.scanner"),
	}

	database := Database{
		Mysql:         v.GetString("database.mysql"),
		Elasticsearch: v.GetString("database.elasticsearch"),
	}

	task := Task{
		DataDir:    v.GetString("task.data_dir"),
		MaxTaskNum: v.GetInt("task.max_task_num"),
	}

	log := Log{
		FileName:     v.GetString("log.file_name"),
		Level:        v.GetString("log.level"),
		DataDir:      v.GetString("log.data_dir"),
		MaxAge:       v.GetInt("log.max_age"),
		MaxSize:      v.GetInt("log.max_size"),
		MaxBackups:   v.GetInt("log.max_backups"),
		Compress:     v.GetBool("log.compress"),
		JsonFormat:   v.GetBool("log.json_format"),
		ShowLine:     v.GetBool("log.show_line"),
		LogInConsole: v.GetBool("log.log_in_console"),
	}

	c := &GlobalCopnfig{
		App:      app,
		Database: database,
		Task:     task,
		Log:      log,
	}

	Gc = *c
	return c
}

func checkAndCreateDir(dir string) (string, error) {
	// 检查目录是否是绝对路径
	isAbsolute := filepath.IsAbs(dir)
	// 如果不是绝对路径，使用当前路径拼接
	if !isAbsolute {
		// 获取当前工作目录的路径
		currentDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(currentDir, dir)
	}

	// 使用 os.Stat() 检查目录是否存在
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return dir, nil
}

func (c *GlobalCopnfig) InitCheck() {
	taskDataDir, err := checkAndCreateDir(c.Task.DataDir)
	if err != nil {
		panic(err)
	}
	c.Task.DataDir = taskDataDir

	logDataDir, err := checkAndCreateDir(c.Log.DataDir)
	if err != nil {
		panic(err)
	}
	c.Log.DataDir = logDataDir

	// 检查目录是否是绝对路径
	isAbsolute := filepath.IsAbs(c.App.Templates)
	// 如果不是绝对路径，使用当前路径拼接
	if !isAbsolute {
		// 获取当前工作目录的路径
		currentDir, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		c.App.Templates = filepath.Join(currentDir, c.App.Templates)
	}

	// 检查扫描器是否是绝对路径
	scannerIsAbsolute := filepath.IsAbs(c.App.Scanner)
	// 如果不是绝对路径，使用当前路径拼接
	if !scannerIsAbsolute {
		// 获取当前工作目录的路径
		currentDir, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		c.App.Scanner = filepath.Join(currentDir, c.App.Scanner)
	}
}

func (c *GlobalCopnfig) GetAppConfig() App {
	return c.App
}

func (c *GlobalCopnfig) GetDatabaseConfig() Database {
	return c.Database
}

func (c *GlobalCopnfig) GetTaskConfig() Task {
	return c.Task
}

func (c *GlobalCopnfig) GetLogConfig() Log {
	return c.Log
}
