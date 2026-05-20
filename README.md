# ☁️ LockCloud — Захищене хмарне сховище

Вебзастосунок для безпечного зберігання файлів з шифруванням, двофакторною аутентифікацією та моніторингом підозрілої активності. 
Розроблено як курсова робота.

---

## 🛠 Технологічний стек

| Компонент | Технологія |
|---|---|
| Backend | Python 3 + Flask |
| База даних | MySQL 8 |
| Шаблонізатор | Jinja2 |
| Frontend | HTML + CSS + Vanilla JS |
| Шифрування | hashlib + hmac + secrets |
| Email | Flask-Mail + SMTP |
| i18n | Власний модуль (EN / UA) |

---

## 📁 Структура проєкту

```
cloudstorage/
├── app.py                  # Головний файл — маршрути та логіка
├── config.py               # Конфігурація (БД, SMTP, ключ шифрування)
├── i18n.py                 # Модуль інтернаціоналізації
├── templates/              # HTML-шаблони (Jinja2)
├── static/                 # CSS, зображення, JS
├── translations/
│   ├── en.json             # Англійські переклади
│   └── ua.json             # Українські переклади
├── uploads/                # Зашифровані файли користувачів
│   └── <user_id>/          # Окрема директорія для кожного користувача
├── venv/                   # Віртуальне середовище Python
├── .gitignore
└── README.md
```

---

## ⚙️ Встановлення та запуск

### 1. Клонування репозиторій

```bash
git clone https://github.com/your-repo/cloudstorage
cd cloudstorage
```

### 2. Створення віртуального середовища

```bash
python3 -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Встановлення залежностей

```bash
pip install flask flask-mail mysql-connector-python werkzeug
```

### 4. Налаштування `config.py`

```python
class Config:
    SECRET_KEY = 'your_secret_key'

    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'your_password'
    MYSQL_DB = 'cloud_storage'

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your@email.com'
    MAIL_PASSWORD = 'your_app_password'

    FILE_ENCRYPTION_KEY = 'your_encryption_key'
```

### 6. Запуск застосунку

```bash
python app.py
```

У браузері: [http://localhost:5000](http://localhost:5000)

---

## ✨ Функціональність

- 🔐 Реєстрація та вхід з двофакторною аутентифікацією (OTP на email)
- 📁 Створення папок із необмеженою вкладеністю
- 📤 Завантаження файлів із шифруванням (Encrypt-then-MAC схема)
- 📥 Скачування та перегляд файлів
- 🗑️ Кошик із відновленням і постійним видаленням
- 🔗 Спільний доступ до файлів між користувачами
- 🛡️ Моніторинг підозрілої активності:
  - вхід з нової IP-адреси
  - активність у нічний час (00:00–06:00)
  - масове видалення файлів
  - ознаки брутфорс-атаки
  - використання нового пристрою
- 👤 Адмін-панель: управління користувачами, журнал подій, налаштування безпеки
- 🌐 Підтримка англійської та української мов

---

## 🔒 Безпека

- Паролі хешуються через **PBKDF2-SHA256** (Werkzeug)
- Файли шифруються власною схемою на основі **SHA-256 CTR + HMAC-SHA256**
- Захист від SQL-ін'єкцій через параметризовані запити
- Захист від IDOR — кожен запит перевіряє `user_id`
- Блокування акаунту після 3 невдалих спроб входу на 15 хвилин
- `hmac.compare_digest` для захисту від timing-атак

---

## 👩‍💻 Автор

Марта Мисишин