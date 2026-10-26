# Отчёт о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедрённой уязвимости

В рамках ДЗ 1 была внедрена уязвимость Open Redirect в приложение на Java с использованием Spring Boot.

- **Тип уязвимости:** Open Redirect
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Файл:** `controller/FileController.java`
- **Уязвимый эндпоинт:** `/redirect`
- **Исправленный эндпоинт:** `/sredirect`
- **Источник:** HTTP-параметр `url`, принимаемый через `@RequestParam`
- **Синк:** `ResponseEntity.location(URI.create(url))`

### Уязвимая реализация

```java
@GetMapping("/redirect")
public ResponseEntity<Void> redirect(@RequestParam String url) {
    return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create(url))
            .build();
}
```

Пользователь может передать произвольный URL, который без проверки используется при формировании заголовка `Location` HTTP-ответа.

Например, при запросе `/redirect?url=https://evil.example` сервер возвращает перенаправление на указанный внешний сайт.

Уязвимость позволяет злоумышленнику использовать доверенный адрес приложения для перенаправления пользователей на сторонние ресурсы, в том числе фишинговые сайты.

### Исправленная реализация

```java
@GetMapping("/sredirect")
public ResponseEntity<Void> safeRedirect(@RequestParam String url) {
    if (!url.startsWith("/") || url.startsWith("//")) {
        return ResponseEntity.badRequest().build();
    }
    return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create(url))
            .build();
}
```

В исправленном эндпоинте добавлена проверка URL. Она отклоняет обычные абсолютные адреса и адреса, начинающиеся с `//`, разрешая относительные пути от корня приложения.

Данная проверка устраняет исходный сценарий перенаправления на произвольный абсолютный URL, однако не является полной защитой от всех вариантов неоднозначной интерпретации URL, например с обратными слешами. Поэтому отсутствие срабатывания SAST само по себе не доказывает полной безопасности исправления.

## 2. Параметры запуска

| Параметр | Значение |
|---|---|
| Сканер | Semgrep OSS |
| Версия | 1.182.1 |
| Язык | Java |
| Фреймворк | Spring Boot |
| Стандартный набор правил | `p/java` |
| Количество стандартных правил | 60 |
| Собственное правило | `custom.spring-responseentity-open-redirect` |
| Коммит, зафиксированный при подготовке | `8c3e6aaf6414d01178412f159a0c2e065e961ebb` |

Сканирование проводилось в каталоге:

`practice/practice1/demo/demoapplication/src/main/java/nsu/security/demoapplication`

Команда стандартного сканирования в PowerShell:

```powershell
& "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts\semgrep.exe" scan --config p/java --json --output semgrep-java.json --verbose .
```

Команда запуска собственного правила:

```powershell
& "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts\semgrep.exe" scan --config .\open-redirect.yaml --json --output custom-rule.json --verbose .
```

### Проверка покрытия

По данным JSON-отчёта Semgrep были просканированы следующие файлы:

```text
controller/FileController.java
controller/HealthController.java
controller/OrderController.java
DemoapplicationApplication.java
model/Order.java
repository/OrderJdbcRepository.java
repository/OrderRepository.java
```

Файл `controller/FileController.java`, содержащий исследуемые эндпоинты, присутствует в списке просканированных файлов.

Сканирование завершилось успешно. Ошибки парсинга и внутренние ошибки Semgrep отсутствуют. Проанализировано приблизительно 100% строк выбранных файлов.

Сканирование ограничивалось файлами, отслеживаемыми Git.

### Файлы результатов

- `semgrep-java.json` — результат сканирования стандартным набором правил.
- `custom-rule.json` — результат сканирования собственным правилом.
- `open-redirect.yaml` — файл собственного правила.

## 3. Результаты сканирования

### 3.1. Сканирование стандартным набором правил

| Версия | Результат | Правило |
|---|---|---|
| Уязвимая `/redirect` | FN | Правила CWE-601 не обнаружили уязвимость |
| Исправленная `/sredirect` | Нет срабатывания | TN при условии корректности исправления |

При запуске набора `p/java` Semgrep применил 60 правил к 7 Java-файлам.

**Результат: 0 находок.**

При этом среди применённых правил присутствовали:

- `java.lang.security.audit.unvalidated-redirect.unvalidated-redirect`
- `java.spring.security.audit.spring-unvalidated-redirect.spring-unvalidated-redirect`

Эти правила предназначены для обнаружения потенциально небезопасных перенаправлений, однако не выявили уязвимость в исследуемом коде.

**Классификация уязвимой версии: FN (False Negative).**

Уязвимость существует, но стандартный набор правил не сообщил о ней, несмотря на успешное сканирование файла с уязвимостью.

Для исправленного эндпоинта срабатываний также не было. Однако окончательная классификация TN требует подтверждения корректности защиты от всех релевантных вариантов внешнего перенаправления.

### 3.2. Сканирование собственным правилом

Для обнаружения используемой конструкции перенаправления было создано собственное правило.

При повторном сканировании получен следующий результат:

| Поле | Значение |
|---|---|
| ID правила | `custom.spring-responseentity-open-redirect` |
| CWE | CWE-601 |
| Файл | `controller/FileController.java` |
| Начальная строка находки | 80 |
| Количество находок | 1 |
| Ошибки сканирования | 0 |
| Сообщение правила | `CWE-601: Untrusted URL reaches ResponseEntity.location().` |

Сканер успешно применил одно правило к 7 Java-файлам и обнаружил одно срабатывание.

Найденный фрагмент на строке 80 относится к методу `/redirect`, находка классифицируется как **TP (True Positive)**, поскольку соответствует внедрённой уязвимости CWE-601.

Второго срабатывания не было. Следовательно, правило не сообщило о проблеме во втором эндпоинте.

## 4. Анализ результатов

### 4.1. Почему стандартный Semgrep не обнаружил уязвимость

В наборе `p/java` присутствует правило:

`java.spring.security.audit.spring-unvalidated-redirect.spring-unvalidated-redirect`

Оно ориентировано на распространённые конструкции перенаправления в Spring MVC, в частности возврат представления с префиксом `redirect:`.

Пример такой реализации:

```java
return "redirect:" + url;
```

В приложении применяется другой способ:

```java
return ResponseEntity
        .status(HttpStatus.FOUND)
        .location(URI.create(url))
        .build();
```

В данном случае перенаправление реализовано через формирование HTTP-ответа со статусом `302 Found` и заголовком `Location`.

Таким образом, отсутствие находки связано не с ошибкой парсинга или пропуском файла, а с ограничениями покрытия используемых правил.

### 4.2. Логика собственного правила

Для обнаружения конкретной конструкции было создано правило `custom.spring-responseentity-open-redirect`.

Правило работает посредством синтаксического сопоставления конструкций Java.

Оно ищет метод, который:

1. Объявлен как Spring-эндпоинт через `@GetMapping`.
2. Принимает строковый параметр `@RequestParam String`.
3. Возвращает `ResponseEntity<Void>`.
4. Использует полученный параметр в `URI.create()` при вызове `.location()`.
5. Не содержит заданную в правиле защитную конструкцию.

Источник недоверенных данных:

```java
@RequestParam String url
```

Опасная операция:

```java
.location(URI.create(url))
```

Проверка, исключаемая собственным правилом:

```java
if (!url.startsWith("/") || url.startsWith("//")) {
    return ResponseEntity.badRequest().build();
}
```

В правиле эта проверка описана через `pattern-not`.

## 5. Доработка: вариант А — собственное правило

Для устранения пропуска исходной уязвимости было разработано специализированное правило Semgrep.

**Файл:** `open-redirect.yaml`

```yaml
rules:
  - id: custom.spring-responseentity-open-redirect
    languages:
      - java
    severity: WARNING
    message: >
      CWE-601: Untrusted URL reaches
      ResponseEntity.location().
    metadata:
      cwe:
        - "CWE-601: URL Redirection to Untrusted Site"
      category: security

    patterns:
      - pattern: |
          @GetMapping(...)
          public ResponseEntity<Void> $METHOD(@RequestParam String $URL) {
            ...
            return ResponseEntity
              .status(...)
              .location(URI.create($URL))
              .build();
          }
      - pattern-not: |
          @GetMapping(...)
          public ResponseEntity<Void> $METHOD(@RequestParam String $URL) {
            ...
            if (!$URL.startsWith("/") || $URL.startsWith("//")) {
              return ResponseEntity.badRequest().build();
            }
            ...
            return ResponseEntity
              .status(...)
              .location(URI.create($URL))
              .build();
          }
```

### Объяснение правила

Правило использует механизм поиска шаблонов Semgrep.

Метапеременная `$URL` обеспечивает совпадение имени параметра, принимаемого из HTTP-запроса, и аргумента `URI.create()`.

`pattern-not` исключает методы с ожидаемой проверкой URL.

**Источник:** `@RequestParam String $URL`.

**Синк:** `.location(URI.create($URL))`.

**Санитайзер:** синтаксически распознаваемая проверка префикса URL, заданная через `pattern-not`.

### Результат запуска

| Версия | Результат | Комментарий |
|---|---|---|
| Уязвимая `/redirect` | TP при подтверждении расположения находки | Обнаружено одно срабатывание CWE-601 |
| Исправленная `/sredirect` | Нет находки | Правило исключило метод с ожидаемой проверкой URL |

При запуске собственного правила Semgrep обнаружил одну находку на строке 80 файла `controller/FileController.java`.

Ошибок парсинга и внутренних ошибок не было.

Таким образом, собственное правило позволило обнаружить конструкцию, не выявленную стандартным набором `p/java`.

## 6. Выводы

В ходе работы было выполнено статическое сканирование Java Spring Boot приложения с помощью Semgrep OSS 1.182.1. Стандартный набор из 60 правил не выявил внедрённую уязвимость Open Redirect (CWE-601), несмотря на успешный анализ файла с исследуемым кодом.

Для обнаружения данной уязвимости было создано специализированное правило, учитывающее использование `ResponseEntity.location(URI.create(url))`. Повторное сканирование обнаружило одно срабатывание в исследуемом контроллере.

Работа продемонстрировала, что наличие правил для определённого CWE не гарантирует обнаружения всех реализаций соответствующей уязвимости. Собственные правила позволяют расширять покрытие SAST, однако их синтаксические ограничения и корректность распознавания исправлений требуют отдельной проверки.
