### AI-Shield Framework v5 final 🛡️

Select Language / Выберите язык / См. описание на языках:
* [English Version (EN)](#english-version)
* [Deutsche Version (DE)](#deutsche-version)
* [Русская версия (RU)](#русская-версия)

* * *

### English Version

**AI-Shield Framework** is an innovative Python desktop application with a graphical user interface (GUI) designed for automated interactive security auditing of Large Language Models (LLMs) based on the global **OWASP Top 10 for LLM Applications** standard.

Unlike static CLI fuzzers (such as Garak), AI-Shield implements a **Multi-turn Adaptive Attacker Agent** approach and **LLM-as-a-Judge** orchestration logic for advanced semantic vulnerability analysis and automated hot-patching.

### 🚀 Killer Features

1.  **Multi-turn Adaptive Attacker Agent:** Instead of single-shot static payloads, an attacker LLM engages in a 3-5 turn dialogue with the target LLM to psychologically manipulate or bypass its defenses based on previous responses.
2.  **Hybrid Architecture (Local Edge AI + Cloud API):** Native support for local, zero-cost, and completely confidential model testing via **Ollama (Llama-3/Mistral)**, as well as cloud providers (OpenRouter/Groq).
3.  **Automated Security Patch Generator:** Once a vulnerability is detected, the system queries a powerful orchestration model to instantly draft a hardened **System Prompt (Guardrail)** to close the exploit.
4.  **SQLite Data Storage:** Built-in session history tracker powered by SQLite to log all multi-turn interactions, logs, and judge scores.
5.  **Auto-Generated Reports:** Automatically exports comprehensive audit compliance data into a clean Markdown report (`AI_Shield_Report.md`).

### 🛠️ Technical Stack

*   **Language:** Python 3.10+
*   **GUI Framework:** CustomTkinter / Tkinter (with multi-threaded `threading` architecture to prevent UI freezing during API calls).
*   **Database:** SQLite3
*   **AI Integration:** REST API (JSON payloads via HTTP Requests), Ollama Local API.

### 📦 Installation & Usage

1.  Clone the repository:

bash

    git clone https://github.com/REDUST-C/ai-shield-agentic-framework.git
    cd ai-shield-agentic-framework
    

Используйте код с осторожностью.

2.  Install the required dependencies:

bash

    pip install -r requirements.txt
    

Используйте код с осторожностью.

3.  Run the application:

bash

    python ai_shield_gui_v5_final.py
    

Используйте код с осторожностью.

* * *

### Deutsche Version

**AI-Shield Framework** ist eine innovative Python-Desktop-Anwendung mit grafischer Benutzeroberfläche (GUI), die für das automatisierte und interaktive Sicherheits-Auditing von Large Language Models (LLMs) gemäß dem globalen **OWASP Top 10 for LLM Applications** Standard entwickelt wurde.

Im Gegensatz zu statischen CLI-Fuzzern (wie Garak) nutzt AI-Shield einen **Multi-turn Adaptive Attacker Agent**\-Ansatz sowie eine **LLM-as-a-Judge** Orchestrierungslogik für fortgeschrittene semantische Schwachstellenanalysen und automatisiertes Patching.

### 🚀 Kernfunktionen

1.  **Adaptiver mehrstufiger Angreifer-Agent:** Anstelle von einfachen statischen Payloads führt ein Angreifer-LLM einen 3-5-stufigen Dialog mit dem Ziel-LLM, um dessen Schutzmechanismen basierend auf den vorherigen Antworten psychologisch zu manipulieren oder zu umgehen.
2.  **Hybrid-Architektur (Lokale Edge AI + Cloud-API):** Native Unterstützung für kostenlose und absolut vertrauliche Modelltests über lokale **Ollama-Container (Llama-3/Mistral)** sowie Cloud-Schnittstellen (OpenRouter/Groq).
3.  **Automatischer Sicherheits-Patch-Generator:** Sobald eine Schwachstelle erkannt wird, generiert das System mithilfe eines starken Orchestrierungsmodells sofort einen gehärteten **System Prompt (Guardrail)**, um den Exploit zu schließen.
4.  **SQLite-Datenspeicherung:** Integrierter Sitzungsverlauf powered by SQLite zur Protokollierung aller Interaktionen, Logs und Sicherheitsbewertungen.
5.  **Automatische Berichterstattung:** Exportiert umfassende Audit-Compliance-Daten vollautomatisch in einen übersichtlichen Markdown-Bericht (`AI_Shield_Report.md`).

### 🛠️ Technischer Stack

*   **Entwicklungssprache:** Python 3.10+
*   **GUI-Framework:** CustomTkinter / Tkinter (mit Multithreading-Architektur `threading`, um ein Einfrieren der GUI bei API-Aufrufen zu verhindern).
*   **Datenbank:** SQLite3
*   **KI-Integration:** REST API (JSON-Payloads via HTTP Requests), Ollama Local API.

### 📦 Installation und Inbetriebnahme

1.  Klonen Sie das Repository:

bash

    git clone https://github.com/REDUST-C/ai-shield-agentic-framework.git
    cd ai-shield-agentic-framework
    

Используйте код с осторожностью.

2.  Installieren Sie die erforderlichen Abhängigkeiten:

bash

    pip install -r requirements.txt
    

Используйте код с осторожностью.

3.  Starten Sie die Anwendung:

bash

    python ai_shield_gui_v5_final.py
    

Используйте код с осторожностью.

* * *

### Русская версия

**AI-Shield Framework** — это инновационное десктопное приложение на Python с графическим интерфейсом (GUI), разработанное для автоматизированного интерактивного аудита безопасности больших языковых моделей (LLM) в соответствии с международным стандартом **OWASP Top 10 for LLM Applications**.

В отличие от статических консольных сканеров (таких как Garak), AI-Shield использует подход **Multi-turn Adaptive Attacker Agent** (адаптивный многошаговый ИИ-хакер) и логику **LLM-as-a-Judge** (ИИ-Судья) для семантического анализа уязвимостей и автоматического создания защитных патчей.

### 🚀 Ключевые возможности

1.  **Адаптивный многошаговый диалог атак:** Инструмент симулирует поведение реального хакера, ведя живой диалог с моделью-целью в 3–5 шагов и пытаясь обойти её этические фильтры на основе её же ответов.
2.  **Гибридная архитектура (Локальный ИИ + Cloud API):** Поддержка бесплатных и конфиденциальных тестов локальных моделей через контейнер **Ollama (Llama-3/Mistral)** на вашем ПК, либо через облачные шлюзы (OpenRouter/Groq).
3.  **Автоматический генератор ИБ-патчей:** При обнаружении уязвимости система использует сильную модель для мгновенной генерации кастомного защитного промпта (System Prompt/Guardrail), закрывающего уязвимость.
4.  **Хранилище данных SQLite:** Встроенная база данных SQLite3 для логирования истории сессий, многошаговых диалогов атак и оценок ИИ-Судьи.
5.  **Автоматическая отчетность:** Генерация подробных комплаенс-отчетов в формате Markdown по результатам сканирования (`AI_Shield_Report.md`).

### 🛠️ Технический стек

*   **Язык разработки:** Python 3.10+
*   **Графический интерфейс:** CustomTkinter / Tkinter (Многопоточная архитектура `threading` для предотвращения зависания GUI во время сетевых запросов).
*   **База данных:** SQLite3
*   **Интеграция ИИ:** REST API (JSON payloads), Ollama Local API, Requests.

### 📦 Установка и запуск

1.  Клонируйте репозиторий:

bash

    git clone https://github.com/REDUST-C/ai-shield-agentic-framework.git
    cd ai-shield-agentic-framework
    

Используйте код с осторожностью.

2.  Установите зависимости:

bash

    pip install -r requirements.txt
    

Используйте код с осторожностью.

3.  Запустите приложение:

bash

    python ai_shield_gui_v5_final.py
    ```
    

Используйте код с осторожностью.
