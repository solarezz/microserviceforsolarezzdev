package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
	"log"
	"net/http"
	"os"
)

type NotificationRequest struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type CachedMessage struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry"` // Время истечения токена
}

var (
	oauthConfig *oauth2.Config
	tokenFile   = "token.json"
	cacheFile   = "message_cache.json"
)

func init() {
	// Загружаем переменные окружения из .env
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	// Настройки OAuth 2.0
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{gmail.GmailSendScope},
		Endpoint:     google.Endpoint,
	}
}

func sendEmail(name, email, message string) error {
	// Получаем токен
	token, err := getToken()
	if err != nil {
		// Если токен отсутствует, сохраняем сообщение в кеше
		log.Println("Токен отсутствует. Сообщение сохранено в кеше.")
		return addToCache(name, email, message)
	}

	// Создаем клиент Gmail
	ctx := context.Background()
	client := oauthConfig.Client(ctx, token)
	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return fmt.Errorf("ошибка создания клиента Gmail: %v", err)
	}

	// Формируем email
	to := os.Getenv("EMAIL_TO")
	subject := "Новое сообщение с сайта"
	encodedSubject := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(subject))) // Кодируем тему письма
	body := fmt.Sprintf("Имя: %s\nEmail: %s\nСообщение:\n%s", name, email, message)
	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", to, encodedSubject, body) // Используем закодированную тему
	gmailMsg := &gmail.Message{
		Raw: base64.URLEncoding.EncodeToString([]byte(msg)),
	}

	// Отправляем email
	_, err = srv.Users.Messages.Send("me", gmailMsg).Do()
	if err != nil {
		return fmt.Errorf("ошибка отправки письма: %v", err)
	}

	log.Printf("Письмо отправлено на %s", to)
	return nil
}

func getToken() (*oauth2.Token, error) {
	// Загружаем токен из файла (если он есть)
	token, err := loadTokenFromFile(tokenFile)
	if err == nil {
		// Проверяем, не истёк ли токен
		if token.Valid() {
			return token, nil
		}

		// Если токен истёк, обновляем его с помощью Refresh Token
		if token.RefreshToken != "" {
			newToken, err := oauthConfig.TokenSource(context.Background(), token).Token()
			if err != nil {
				return nil, fmt.Errorf("ошибка обновления токена: %v", err)
			}

			// Сохраняем новый токен
			saveTokenToFile(tokenFile, newToken)
			return newToken, nil
		}
	}

	// Если токена нет или он недействителен, запрашиваем новый
	authURL := oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Перейди по ссылке для авторизации: \n%v\n", authURL)

	// Ждём, пока пользователь авторизуется и сервер получит код через /callback
	// Код будет обработан в callbackHandler
	return nil, fmt.Errorf("токен отсутствует или недействителен")
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Извлекаем код авторизации из URL
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Код авторизации не найден", http.StatusBadRequest)
		return
	}

	// Сохраняем код авторизации в файл
	err := saveAuthCodeToFile("auth_code.txt", code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка сохранения кода авторизации: %v", err), http.StatusInternalServerError)
		return
	}

	// Выводим код авторизации на странице
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Код авторизации: %s\nТокен будет обновлён автоматически.", code)))

	// Обмениваем код на токен
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Ошибка обмена кода на токен: %v", err)
		return
	}

	// Сохраняем токен в файл
	err = saveTokenToFile(tokenFile, token)
	if err != nil {
		log.Printf("Ошибка сохранения токена: %v", err)
		return
	}

	log.Println("Токен успешно сохранён.")

	// Отправляем все закешированные сообщения
	err = sendCachedMessages()
	if err != nil {
		log.Printf("Ошибка отправки закешированных сообщений: %v", err)
		return
	}

	log.Println("Все закешированные сообщения отправлены.")
}

func saveAuthCodeToFile(file string, code string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(code)
	return err
}

func loadTokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

func saveTokenToFile(file string, token *oauth2.Token) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(token)
}

func loadCache() ([]CachedMessage, error) {
	// Проверяем, существует ли файл
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return []CachedMessage{}, nil // Если файла нет, возвращаем пустой кеш
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия файла кеша: %v", err)
	}
	defer file.Close()

	var cache []CachedMessage
	err = json.NewDecoder(file).Decode(&cache)
	if err != nil {
		if err.Error() == "EOF" {
			return []CachedMessage{}, nil // Если файл пуст, возвращаем пустой кеш
		}
		return nil, fmt.Errorf("ошибка декодирования кеша: %v", err)
	}

	return cache, nil
}

func saveCache(cache []CachedMessage) error {
	file, err := os.Create(cacheFile)
	if err != nil {
		return fmt.Errorf("ошибка создания файла кеша: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Добавляем форматирование для удобства чтения
	return encoder.Encode(cache)
}

func addToCache(name, email, message string) error {
	cache, err := loadCache()
	if err != nil {
		return fmt.Errorf("ошибка загрузки кеша: %v", err)
	}

	// Добавляем новое сообщение в кеш
	cache = append(cache, CachedMessage{
		Name:    name,
		Email:   email,
		Message: message,
	})

	// Сохраняем обновлённый кеш
	return saveCache(cache)
}

func clearCache() error {
	return os.Remove(cacheFile)
}

func sendCachedMessages() error {
	cache, err := loadCache()
	if err != nil {
		return fmt.Errorf("ошибка загрузки кеша: %v", err)
	}

	if len(cache) == 0 {
		log.Println("Кеш пуст. Нечего отправлять.")
		return nil
	}

	for _, msg := range cache {
		err := sendEmail(msg.Name, msg.Email, msg.Message)
		if err != nil {
			return fmt.Errorf("ошибка отправки закешированного сообщения: %v", err)
		}
	}

	// Очищаем кеш после успешной отправки
	return clearCache()
}

func notificationHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Получен запрос на /send-notification")

	var req NotificationRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Ошибка при чтении данных: %v", err)
		http.Error(w, "Ошибка при чтении данных", http.StatusBadRequest)
		return
	}

	log.Printf("Данные: Имя=%s, Email=%s, Сообщение=%s", req.Name, req.Email, req.Message)

	err = sendEmail(req.Name, req.Email, req.Message)
	if err != nil {
		log.Printf("Ошибка при отправке уведомления: %v", err)
		http.Error(w, "Ошибка при отправке уведомления", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Уведомление отправлено!"))
}

func main() {
	// Настраиваем CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://solarezz.dev", "http://localhost:8080", "https://www.solarezz.dev", "http://localhost:8000", "http://127.0.0.1:8000"}, // Укажи домены, с которых разрешены запросы
		AllowedMethods:   []string{"POST", "GET", "OPTIONS"},                                                                                                      // Разрешенные HTTP-методы
		AllowedHeaders:   []string{"Content-Type"},                                                                                                                // Разрешенные заголовки
		AllowCredentials: true,                                                                                                                                    // Разрешить передачу куки и авторизационных данных
		Debug:            true,                                                                                                                                    // Включить логирование CORS (опционально)
	})

	// Оборачиваем маршруты в CORS
	handler := c.Handler(http.DefaultServeMux)

	http.HandleFunc("/send-notification", notificationHandler)
	http.HandleFunc("/callback", callbackHandler)

	fmt.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
