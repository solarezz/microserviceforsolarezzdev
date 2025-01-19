package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"github.com/rs/cors"
)

// Структура для входящего запроса
type NotificationRequest struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

// Обработчик для /send-notification
func notificationHandler(w http.ResponseWriter, r *http.Request) {
	// Разрешаем CORS для всех запросов
	w.Header().Set("Access-Control-Allow-Origin", "https://solarezz.dev")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRFToken")

	// Обрабатываем OPTIONS запрос (preflight)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Обрабатываем POST запрос
	var req NotificationRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Ошибка при чтении данных: %v", err)
		http.Error(w, "Ошибка при чтении данных", http.StatusBadRequest)
		return
	}

	// Логируем данные
	log.Printf("Получено сообщение: Имя=%s, Email=%s, Сообщение=%s", req.Name, req.Email, req.Message)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Сообщение успешно отправлено!",
	})
}

func main() {
	// Настраиваем CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://solarezz.dev"}, // Разрешаем запросы только с этого домена
		AllowedMethods:   []string{"POST", "GET", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-CSRFToken"}, // Разрешаем заголовки
		AllowCredentials: true,
		Debug:            true, // Включаем логирование CORS
	})

	// Создаем мультиплексор и регистрируем обработчики
	mux := http.NewServeMux()
	mux.HandleFunc("/send-notification", notificationHandler)

	// Оборачиваем мультиплексор в CORS
	handler := c.Handler(mux)

	// Запускаем сервер
	fmt.Println("Сервер запущен на http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
