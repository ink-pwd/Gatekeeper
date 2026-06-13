package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ink-pwd/Gatekeeper/internal/consts"
	"github.com/ink-pwd/Gatekeeper/internal/email"
	"github.com/ink-pwd/Gatekeeper/internal/model"
	"github.com/ink-pwd/Gatekeeper/internal/security"
	"github.com/ink-pwd/Gatekeeper/internal/storage"
	"github.com/ink-pwd/Gatekeeper/logger"
)

type AuthHandler struct {
	log          logger.Logger
	db           *sql.DB
	secret       string
	clientRedis  *storage.ClientRedis
	sender       *email.Sender
	timeDurRedis int
	protocol     string
	server       string
	port         string
	timeDurJWT   int
}

func NewAuthHandler(log logger.Logger, db *sql.DB, clientRedis *storage.ClientRedis,
	sender *email.Sender, timeDurRedis, timeDurJWT int, protocol, server, secret, port string) *AuthHandler {
	return &AuthHandler{
		log:          log,
		db:           db,
		secret:       secret,
		clientRedis:  clientRedis,
		sender:       sender,
		timeDurRedis: timeDurRedis,
		protocol:     protocol,
		server:       server,
		port:         port,
		timeDurJWT:   timeDurJWT,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		uuid  string
		exist int64
		user  *model.User
		link  string
		ok    bool
	)
	/*
		Получаем json запроса, его будем использовать для записи в бд
		используем Redis для хранения почты по ключу верификации
		для изменения статуса пользователя на верифицированного
	*/
	
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	/*
		Получаем body запроса
	*/
	err = json.NewDecoder(r.Body).Decode(&user)

	//закрываем чтение тела запроса
	r.Body.Close()
	if err != nil {
		h.log.Error("json decode error: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	/*
		Проверяем наличие пользователя с указанным email
	*/
	if storage.CheckUser(user.Email, h.db, h.log) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	/*
		Сразу хешируем пароль пользователя!
	*/
	user.Password, err = security.CryptoHash(user.Password)
	if err != nil {
		h.log.Error("crypho hash err: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for {
		uuid = security.GetUUID()
		exist, err = h.clientRedis.Exist(uuid)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if exist == 0 {
			break
		}

	}
	/*
		записываем в redis
		uuid token => email для дальнейшей верификации
		timeDuration - время на подтверждение почты
	*/
	h.clientRedis.Set(uuid, []byte(user.Email), h.timeDurRedis)

	/*
		Сразу делаем запись в бд
		значение поля verify будет false
	*/
	ok = storage.AddUser(user.Email, user.Password, h.db, h.log)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	/*
		Асинхронно отправляем письмо,
		что бы пользователь долго не ждал ответ от свервера
	*/
	link = fmt.Sprintf("%s://%s%s%s?token=%s", h.protocol, h.server, h.port, consts.VERIFY, uuid)
	go h.sender.SendMessage(user.Email, link, h.timeDurRedis)

	h.log.Info("success send code: %s", uuid)
	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var (
		user          *model.User
		jwtToken      string
		err           error
		password_hash string
	)
	/*
		Получаем информацию от пользователя
	*/

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	/*
		Получаем body запроса
	*/
	err = json.NewDecoder(r.Body).Decode(&user)
	r.Body.Close()

	if err != nil {
		h.log.Error("json decode error: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	password_hash = storage.GetUserByEmail(user.Email, user.Password, h.db, h.log)
	if !security.Compare(user.Password, password_hash) {
		/*
			возвращаем 401, что значит, что данные введены неверно
			никаких уточнений не делаем для защиты,
			пользователь не должен знать имеется ли такой email в базе или нет
		*/
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	/*
		Получаем jwt-токен
	*/
	jwtToken, err = security.CreateToken(user.Email, h.secret, h.timeDurJWT)
	if err != nil {
		h.log.Error("token creation error: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	h.log.Info("success login user: %s", user.Email)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": jwtToken})
}

func (h *AuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var (
		jwtToken string
		email    string
		err      error
	)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jwtToken = r.Header.Get("Authorization")
	if jwtToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	/*
		Убираем префикс "Bearer "
	*/
	if len(jwtToken) > 7 && jwtToken[:7] == "Bearer " {
		jwtToken = jwtToken[7:]
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	/*
		Валидируем токен
	*/
	email, err = security.ValidateToken(jwtToken, h.secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	/*
		Токен валиден, возвращаем email
	*/
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"email": email,
		"valid": "true",
	})
}

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var (
		token string
		err   error
		email string
	)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	/*
		Получаем токен
	*/
	token = r.URL.Query().Get("token")
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	/*
		Получаем email пользователя
	*/
	email, err = h.clientRedis.Get(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	/*
		Верифицируем пользователя
	*/
	storage.VerifyUser(email, h.db, h.log)

	/*
		Удаляем пользователя
	*/
	err = h.clientRedis.Del(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.log.Error("redis del: %s", err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
}
