# Python DNS Server with Resolver and Cache

Этот проект реализует упрощённый DNS-сервер на Python, способный:
- Принимать DNS-запросы по UDP
- Разрешать имена через корневой сервер (198.41.0.4)
- Поддерживать кэширование ответов (в `cach.txt`)
- Автоматически обновлять TTL и удалять устаревшие записи
- Возвращать клиенту DNS-ответ в бинарном виде

---

## 📁 Структура

### Основные файлы:

- `SERVERS.py` — основной сервер, принимающий DNS-запросы
- `Messages.py` — сборка и разбор DNS-сообщений
- `Header.py`, `Questions.py`, `Answers.py` — разбор и упаковка отдельных секций DNS
- `DNS_EXCEPTIONS.py` — кастомные исключения

### Дополнительные файлы:

- `cach.txt` — кэш DNS-записей
- `logs.txt` — время последнего обновления кэша

---

## 📦 Зависимости

- Python 3.7+
- Библиотеки: `socket`, `pickle`, `time`, `threading`, `random`

---

## 🚀 Запуск

1. Убедитесь, что порт `53` свободен (или измените его в `SERVERS.py`)
2. Запустите DNS-сервер:

```bash
python SERVERS.py
```

3. Отправьте DNS-запрос через `dig` или сторонний клиент на `localhost:53`

---

## ⚙️ Как работает

- Сервер принимает UDP-запрос
- Пытается найти ответ в кэше
- Если нет — обращается к корневому DNS-серверу
- Сохраняет и обновляет кэш с учётом TTL
- Отправляет бинарный DNS-ответ клиенту

---

## 🛠 Особенности

- Использует структурированное представление DNS-пакетов
- Поддерживает типы A, NS, AAAA, SOA, и другие
- Читает и пишет кэш в файл, сохраняя состояние между запусками
- Поддерживает распаковку сжатых DNS-имен (с помощью offset'ов)

---

## 🔒 Исключения

- `DNS_NAME_EXCEPTION` — имя не найдено
- `DNS_TIME_OUT_EXCEPTION` — сервер не ответил вовремя
- `DNS_NOT_IMPLEMENT_EXCEPTION` — неподдерживаемый тип запроса

---

Автор: [Укажи имя или ник]  
Лицензия: MIT