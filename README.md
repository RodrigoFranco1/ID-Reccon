# Dork-Reccon
# 🕵️ Google Dorker con Capturas y Reporte Visual

Herramienta avanzada para automatizar búsquedas de información sensible con Google Dorking utilizando la [API de SerpAPI](https://serpapi.com/). Realiza búsquedas paralelas sobre múltiples extensiones y palabras clave, captura pantallas de los resultados y genera un reporte HTML visual.

Ideal para OSINT, Red Team, auditorías de exposición digital y análisis forense.

---

## 🚀 Funcionalidades principales

- ✅ Automatización de dorking con `SerpAPI`
- 🧠 Operadores avanzados: `intext`, `intitle`, `inurl`
- 🌐 Soporte para subdominios
- 📂 Entrada de múltiples dominios desde archivo
- ⚡ Paralelismo con `ThreadPoolExecutor`
- 🔁 Reintentos robustos ante errores o `429 Too Many Requests`
- 📸 Capturas automáticas de pantalla por cada resultado
- 🖥️ Generación de reporte visual en HTML con las URLs y sus screenshots
- 📄 Salida JSON y TXT
- 🧾 Logs en consola y archivo (`dorking_errors.log`)

---

## 🧪 Requisitos

- Python 3.8 o superior
- API Key válida de [SerpAPI](https://serpapi.com/)
- Navegador Google Chrome instalado (para capturas)

### 📦 Instalación de dependencias

```bash
pip install -r requirements.txt

