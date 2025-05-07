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

## Requisitos

- Python 3.8 o superior
- API Key válida de [SerpAPI](https://serpapi.com/), (Puede ser la versióon gratuita).
- Navegador Google Chrome instalado (para capturas)

### Instalación de dependencias

```bash
pip install -r requirements.txt
```
### Uso
```bash
- python google_dorker.py [opciones] <dominio o archivo>
```
```bash
- python google_dorker.py dominios.txt -f -p 2 -s
```
- El archivo dominios.txt debe tener un dominio por línea (sin http:// ni /).
---

### Uso recomendado en Kali Linux 
- Kali Linux ya no permite modificar paquetes del Python base (/usr/lib/python3). Por eso se recomienda el uso de un entorno virtual para instalar los requerimientos.

```bash
# Crear entorno virtual
python3 -m venv ~/local

# Activar entorno
source ~/local/bin/activate

# Instalar dependencias en entorno aislado
pip install -r requirements.txt
Esto asegura un entorno limpio, sin modificar el sistema base de Kali.
```
---

## Opciones CLI

- `-f`, `--file`: Indica que entrada es un archivo de texto
- `-e`, `--extensions`: Extensiones separadas por coma (pdf,json,env)
- `-k`, `--keywords`: Palabras clave separadas por coma (password,token)
- `-p`, `--pages`: Número de páginas por extensión (default: 1)
- `-s`, `--subdomains`: Buscar también en subdominios (site:*.dominio)
- `-a`, `--advanced`: Usa operadores avanzados (intext:, intitle:, inurl:)
- `-w`, `--workers`: Número de hilos paralelos (default: 5)
- `-o`, `--outdir`: Carpeta donde guardar resultados (default: ./resultados)
- `--sleep`: Pausa entre peticiones (default: 1.0 seg)

---

## Archivos generados

- resultados/dorking_results.json: resultados estructurados
- resultados/dorking_links.txt: solo URLs
- resultados/screenshots/*.png: capturas por resultado
- resultados/dorking_report.html: informe visual navegable
- resultados/dorking_errors.log: errores registrados



