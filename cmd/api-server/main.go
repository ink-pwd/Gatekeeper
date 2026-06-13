package main

import (
	"database/sql"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ink-pwd/Gatekeeper/internal/consts"
	"github.com/ink-pwd/Gatekeeper/internal/email"
	"github.com/ink-pwd/Gatekeeper/internal/handler"
	"github.com/ink-pwd/Gatekeeper/internal/storage"
	"github.com/ink-pwd/Gatekeeper/logger"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

func main() {
	/*
		Это демонстрационный проект создания api
		для авторизации/валидации/регистрации/подтверждения по email

		в котором происходит:
		временное хранение данных в redis(ttl = 10 min), отправка сообщений smtp
		работа с бд(postgresql), шифрование паролей с помощью bcrypt,
		создание jwt-токена, uuid который используется в качестве ключа верификации по email,
		автоудаление неверифицированных пользователей.

		Проект полностью контейнеризирован с помощью Docker.
		Реализована многоконтейнерная оркестрация через Docker Compose!
	*/

	var (
		err           error
		mux           *http.ServeMux
		log           logger.Logger
		handl         *handler.AuthHandler
		listenaddr    string
		server        string
		redisHost     string
		port          string
		protocol      string
		redisPort     string
		connStr       string
		secret        string
		fromEmail     string
		password      string
		hostsmtp      string
		portsmtp      string
		timeEnv       string
		timeDurDelete int
		timeDurRedis  int
		timeDurJWT    int
		ticker        *time.Ticker
		sender        *email.Sender
		db            *sql.DB
		redClient     *storage.ClientRedis
		connect       bool
	)

	/*
		Инициализация логера
	*/
	log = logger.NewStdLogger()

	/*
		Загружаем окружение
	*/
	err = godotenv.Load()
	if err != nil {
		log.Fatal("environment startup error: %s", err.Error())
		return
	}
	listenaddr = os.Getenv("LISTENADDR")
	server = os.Getenv("SERVER")
	connStr = os.Getenv("DB")
	redisHost = os.Getenv("REDISHOST")
	secret = os.Getenv("SECRET")
	protocol = os.Getenv("PROTOCOL")
	port = os.Getenv("PORT")
	redisPort = os.Getenv("REDIS")
	hostsmtp = os.Getenv("HOSTSMTP")
	portsmtp = os.Getenv("PORTSMTP")
	fromEmail = os.Getenv("EMAIL")
	password = os.Getenv("PASSWORD")
	timeEnv = os.Getenv("TIMEDURATIONREDIS")

	/*
		Превращаем время взятое из окружение в int
	*/
	timeDurRedis, err = strconv.Atoi(timeEnv)
	if err != nil {
		log.Fatal("specify an integer time duration redis in .env: %s", err.Error())
	}

	timeEnv = os.Getenv("TIMEDURATIONDELETE")

	timeDurDelete, err = strconv.Atoi(timeEnv)
	if err != nil {
		log.Fatal("specify an integer time duration delete in .env: %s", err.Error())
	}

	timeEnv = os.Getenv("TIMEDURATIONJWT")

	timeDurJWT, err = strconv.Atoi(timeEnv)
	if err != nil {
		log.Fatal("specify an integer time duration jwt in .env: %s", err.Error())
	}

	/*
		Cоздаем структуру для отправки сообщений
	*/
	sender = email.NewSender(fromEmail, password, hostsmtp, portsmtp)

	/*
		Подключаемся к бд
	*/
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("error db connect: %s", err.Error())
		return
	}
	log.Info("success connect to db")

	/*
		Подключаемся к redis
	*/
	redClient = storage.NewClient(redis.NewClient(&redis.Options{
		Addr:     redisHost + redisPort,
		Password: "",
		DB:       0,
	}))

	connect = redClient.Ping()
	if !connect {
		log.Fatal("error redis connect")
	}
	log.Info("success redis connect %s%s", server, redisPort)

	/*
		Инициализация зависимостей
	*/
	mux = http.NewServeMux()
	handl = handler.NewAuthHandler(log, db, redClient, sender, timeDurRedis, timeDurJWT, protocol, server, secret, port)

	/*
		Регистрируем маршруты
	*/
	mux.HandleFunc(consts.REGISTER, handl.Register)
	mux.HandleFunc(consts.LOGIN, handl.Login)
	mux.HandleFunc(consts.VALIDATE, handl.Validate)
	mux.HandleFunc(consts.VERIFY, handl.Verify)

	/*
		Запускаем автоудаление не верифицированных пользователей
		асинхронно, что бы не мешало выполнению основного кода
	*/
	go func() {
		ticker = time.NewTicker(time.Duration(timeDurDelete) * time.Minute)
		defer ticker.Stop()

		log.Info("remove unverified users")
		storage.DeleteNonVerify(db, log)
	}()

	/*
		Запуск сервера
	*/
	err = http.ListenAndServe(listenaddr+port, mux)
	if err != nil {
		log.Fatal("the server did not start: %s", err.Error())
		return
	}
	log.Info("server has been started at %s", listenaddr+port)
}
