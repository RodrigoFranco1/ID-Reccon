# Information Disclosure Hunter
# 🎯 Advanced Google Dorking for Information Disclosure Detection

Herramienta especializada para detectar **Information Disclosure** mediante Google Dorking automatizado, optimizada para **Pentesting**, **Red Team** y **Bug Bounty**. Utiliza la [API de SerpAPI](https://serpapi.com/) con algoritmos de scoring inteligente para priorizar hallazgos críticos.

Ideal para descubrir credenciales expuestas, archivos de configuración, APIs keys, y cualquier información sensible públicamente accesible.

---

## 🔥 Funcionalidades avanzadas para Pentesting

- 🎯 **Sistema de Scoring Inteligente**: Prioriza automáticamente los hallazgos más críticos (0-10)
- 🔍 **32+ Extensiones Críticas**: `.env`, `.config`, `.key`, `.pem`, `.sql`, `.bak`, etc.
- 🧠 **Keywords Categorizadas**: Credenciales, APIs, bases de datos, configuración
- 📥 **Análisis de Contenido**: Descarga y analiza archivos sensibles automáticamente
- 🔍 **Detección de Patrones**: Regex para `API_KEY="..."`, `PASSWORD="..."`, etc.
- 📊 **Dashboard HTML Interactivo**: Reporte visual con código de colores por riesgo
- ⚡ **Paralelismo Optimizado**: Procesamiento por categorías de información sensible
- 🌐 **Soporte para Subdominios**: Escaneo completo de infraestructura
- 🔁 **Reintentos Robustos**: Manejo inteligente de rate limiting
- 📸 **Screenshots Automáticos**: Evidencia visual de hallazgos críticos
- 📁 **Evidencia Completa**: Archivos descargados + análisis + screenshots

---

## 🚀 Instalación

### Requisitos
- Python 3.8 o superior
- API Key válida de [SerpAPI](https://serpapi.com/) (versión gratuita disponible)
- Google Chrome instalado (para capturas)

### Configuración de dependencias

```bash
pip install -r requirements.txt
```

### Variable de entorno
```bash
export SERPAPI_KEY="tu_api_key_aqui"
```

### Uso recomendado en Kali Linux 
Kali Linux ya no permite modificar paquetes del Python base. Se recomienda usar un entorno virtual:

```bash
# Crear entorno virtual
python3 -m venv ~/pentest-env

# Activar entorno
source ~/pentest-env/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Configurar API key
export SERPAPI_KEY="tu_api_key"
```

---

## 🎯 Uso para Pentesting/Red Team

### Escaneo básico enfocado en credenciales
```bash
python3 disclosure_hunter.py -i target.com -c credentials,api_secrets
```

### Escaneo completo con subdominios
```bash
python3 disclosure_hunter.py -i target.com -s -c credentials,api_secrets,config,database -p 3
```

### Escaneo desde archivo con múltiples objetivos
```bash
python3 disclosure_hunter.py -f targets.txt -s --min-score 5.0
```

### Escaneo agresivo para red team
```bash
python3 disclosure_hunter.py -i target.com -s -p 5 -w 5 --min-score 3.0 -c credentials,api_secrets,config,database,backup
```

### Ejemplo de archivo de targets
```
target1.com
target2.com
subdomain.target3.com
```

---

## ⚙️ Opciones CLI

### Opciones principales
- `-i`, `--input`: Dominio objetivo o archivo de dominios
- `-f`, `--file`: Indica que la entrada es un archivo de texto
- `-c`, `--categories`: Categorías de información sensible (default: credentials,api_secrets,config,database)
- `-p`, `--pages`: Número de páginas por categoría (default: 2)
- `-s`, `--subdomains`: Buscar también en subdominios (`site:*.dominio`)
- `-w`, `--workers`: Número de hilos paralelos (default: 3)
- `-o`, `--outdir`: Directorio de salida (default: disclosure_results)
- `--sleep`: Pausa entre peticiones en segundos (default: 2.0)
- `--min-score`: Score mínimo de sensibilidad para incluir resultado (default: 3.0)

### Categorías disponibles
- **`credentials`**: Passwords, secrets, tokens, private keys
- **`api_secrets`**: API keys, bearer tokens, OAuth, JWT, client secrets
- **`database`**: Usernames, connection strings, MySQL, PostgreSQL
- **`config`**: Admin configs, settings, environment files
- **`financial`**: SSN, credit cards, payment info, billing
- **`infrastructure`**: Server configs, staging, development, debug
- **`backup`**: Backup files, dumps, exports, archives
- **`email_systems`**: SMTP, mail servers, Exchange
- **`security`**: VPN configs, firewall rules, vulnerability reports

---

## 📊 Archivos generados

### Estructura de salida
```
disclosure_results/
├── information_disclosure.json     # Resultados estructurados con scores
├── disclosure_report.html          # Dashboard HTML interactivo
├── information_disclosure.log      # Log detallado de ejecución
├── screenshots/                    # Capturas de hallazgos críticos
│   ├── a1b2c3d4e5f6.png
│   └── f6e5d4c3b2a1.png
└── downloaded_files/               # Archivos sensibles descargados
    ├── sensitive_file_1.txt
    └── sensitive_file_2.txt
```

### Contenido del JSON
```json
{
  "title": "Admin Configuration File",
  "link": "https://target.com/config/admin.env",
  "snippet": "Environment configuration with database credentials...",
  "sensitivity_score": 8.5,
  "extension": "env",
  "categoria": "credentials",
  "screenshot": "screenshots/a1b2c3d4e5f6.png",
  "content_analysis": {
    "sensitive_patterns": ["DB_PASSWORD=\"secret123\""],
    "severity": "high",
    "details": ["Found sensitive pattern: password", "Found term: secret"]
  }
}
```

---

## 🎯 Ejemplos de uso por escenario

### Bug Bounty - Búsqueda rápida de APIs expuestas
```bash
python3 disclosure_hunter.py -i target.com -c api_secrets -p 2 --min-score 6.0
```

### Pentest interno - Análisis completo de subdominios
```bash
python3 disclosure_hunter.py -i client.com -s -c credentials,config,database,backup -p 4 -w 3
```

### Red Team - Reconocimiento sigiloso
```bash
python3 disclosure_hunter.py -f targets.txt -c credentials,api_secrets --sleep 3.0 --min-score 4.0
```

### OSINT - Investigación de múltiples objetivos
```bash
python3 disclosure_hunter.py -f companies.txt -s -c credentials,financial,infrastructure -p 3
```

---

## 📈 Sistema de Scoring

### Niveles de riesgo
- **🔴 Alto (7.0-10.0)**: Credenciales, API keys, archivos de configuración críticos
- **🟡 Medio (4.0-6.9)**: Archivos de backup, información interna, logs
- **🟢 Bajo (0.0-3.9)**: Documentos públicos, información general

### Factores de scoring
- **Extensión del archivo**: `.env`, `.key`, `.config` = +2.0 puntos
- **Keywords críticas**: `password`, `secret`, `api_key` = +3.0 puntos
- **Patrones en URL**: `admin`, `config`, `backup` = +2.0 puntos
- **Contenido sensible**: Credenciales en snippet = +3.0 puntos

---

## 🔍 Extensiones monitoreadas

### Archivos críticos de configuración
- `.env`, `.config`, `.ini`, `.conf`, `.cfg`, `.properties`, `.yaml`, `.yml`

### Archivos de seguridad y certificados
- `.key`, `.pem`, `.crt`, `.p12`, `.pfx`, `.jks`

### Archivos de respaldo y temporales
- `.bak`, `.backup`, `.old`, `.log`, `.tmp`, `.temp`, `.swp`

### Código fuente con posibles secretos
- `.js`, `.php`, `.asp`, `.aspx`, `.jsp`, `.py`, `.rb`, `.go`, `.java`

### Bases de datos y archivos estructurados
- `.sql`, `.db`, `.sqlite`, `.mdb`, `.dump`, `.json`, `.xml`, `.csv`

---

## 🛡️ Consideraciones de seguridad

### Uso ético
- ✅ Solo usar en dominios propios o con autorización explícita
- ✅ Respetar los términos de servicio de SerpAPI
- ✅ No automatizar descargas masivas sin permiso
- ✅ Reportar vulnerabilidades encontradas de manera responsable

### Rate limiting
- La herramienta respeta automáticamente los límites de API
- Configurar `--sleep` apropiadamente para evitar detección
- Usar `--workers` conservadoramente en escaneos largos

---

## 🔧 Troubleshooting

### Error: "SERPAPI_KEY not found"
```bash
export SERPAPI_KEY="tu_api_key_aqui"
# O agregarlo a ~/.bashrc para persistencia
```

### Error de Chrome/Selenium
```bash
# Ubuntu/Debian
sudo apt install chromium-browser chromium-chromedriver

# Kali Linux
sudo apt install chromium chromium-driver
```

### Rate limiting excesivo
```bash
# Aumentar el delay entre requests
python3 disclosure_hunter.py -i target.com --sleep 5.0 -w 1
```

---

## 📚 Recursos adicionales

- [OWASP Information Exposure](https://owasp.org/www-community/Improper_Error_Handling)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- [SerpAPI Documentation](https://serpapi.com/search-api)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork del repositorio
2. Crear branch para feature (`git checkout -b feature/mejora`)
3. Commit de cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push al branch (`git push origin feature/mejora`)
5. Abrir Pull Request

---

## ⚖️ Licencia

Este proyecto está bajo licencia MIT. Uso responsable únicamente.

---

## 🏆 Créditos
F0r4j1do 💀
Desarrollado para la comunidad de seguridad informática. Inspirado en técnicas de OSINT y metodologías de pentesting modernas.

**⚠️ Disclaimer**: Esta herramienta está destinada únicamente para uso ético en pruebas de penetración autorizadas, bug bounty programs y auditorías de seguridad propias. El uso malintencionado está prohibido.
