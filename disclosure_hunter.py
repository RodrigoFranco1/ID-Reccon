import argparse
import json
import logging
import os
import sys
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_result,
)

# =====================================================================================
# CONFIGURACIONES OPTIMIZADAS PARA INFORMATION DISCLOSURE - PENTESTING/RED TEAM
# =====================================================================================

# Extensiones críticas para Information Disclosure
CRITICAL_EXTENSIONS = [
    # Documentos con potencial información sensible
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
    # Archivos de configuración críticos
    "env", "config", "ini", "conf", "cfg", "properties", "yaml", "yml",
    # Archivos de código fuente que pueden contener secretos
    "js", "php", "asp", "aspx", "jsp", "py", "rb", "go", "java",
    # Archivos de respaldo y logs
    "bak", "backup", "old", "log", "tmp", "temp", "swp",
    # Archivos de base de datos y SQL
    "sql", "db", "sqlite", "mdb", "dump",
    # Archivos JSON/XML que pueden contener APIs
    "json", "xml", "csv",
    # Archivos específicos de sistemas
    "key", "pem", "crt", "p12", "pfx", "jks"
]

# Keywords optimizadas para detectar information disclosure
SENSITIVE_KEYWORDS = {
    "credentials": ["password", "passwd", "pwd", "secret", "token", "api_key", "private_key"],
    "internal_info": ["confidential", "internal", "restricted", "private", "classified"],
    "database": ["username", "database", "connection", "mysql", "postgresql", "oracle"],
    "config": ["admin", "config", "configuration", "settings", "env"],
    "api_secrets": ["api_key", "bearer", "oauth", "jwt", "client_secret", "access_token"],
    "financial": ["ssn", "credit_card", "bank", "payment", "billing"],
    "infrastructure": ["server", "staging", "development", "test", "debug"],
    "email_systems": ["smtp", "email", "mail", "exchange"],
    "security": ["vpn", "firewall", "vulnerability", "pentest", "security"],
    "backup": ["backup", "dump", "export", "archive", "old"]
}

# Operadores avanzados específicos para information disclosure
DISCLOSURE_OPERATORS = {
    "sensitive_files": 'intitle:"index of" OR intitle:"directory listing"',
    "error_pages": 'intext:"sql syntax" OR intext:"mysql error" OR intext:"warning:"',
    "login_pages": 'inurl:login OR inurl:admin OR inurl:dashboard',
    "backup_files": 'inurl:backup OR inurl:old OR inurl:bak',
    "config_exposed": 'intext:"DB_PASSWORD" OR intext:"API_KEY" OR intext:"SECRET"',
    "development": 'inurl:dev OR inurl:test OR inurl:staging OR inurl:demo'
}

# Patrones de alta prioridad para análisis de contenido
HIGH_PRIORITY_PATTERNS = [
    r'password\s*[=:]\s*["\']([^"\']+)["\']',
    r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
    r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
    r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
    r'database[_-]?url\s*[=:]\s*["\']([^"\']+)["\']',
    r'smtp[_-]?password\s*[=:]\s*["\']([^"\']+)["\']',
    r'private[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
    r'aws[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']'
]

API_URL = "https://serpapi.com/search"

class SensitivityScorer:
    """Clase para evaluar la sensibilidad de los resultados encontrados"""
    
    @staticmethod
    def score_result(result: Dict[str, Any]) -> float:
        """Asigna un score de sensibilidad de 0-10"""
        score = 0.0
        title = result.get('title', '').lower()
        snippet = result.get('snippet', '').lower()
        link = result.get('link', '').lower()
        
        # Scoring por extensión de archivo
        for ext in CRITICAL_EXTENSIONS[:10]:  # Top 10 más críticas
            if ext in link:
                score += 2.0
                break
        
        # Scoring por keywords sensibles
        for category, keywords in SENSITIVE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in title or keyword in snippet:
                    if category in ['credentials', 'api_secrets']:
                        score += 3.0
                    elif category in ['database', 'config']:
                        score += 2.5
                    else:
                        score += 1.5
        
        # Bonus por patrones específicos
        if any(pattern in link for pattern in ['admin', 'config', 'backup', 'dev']):
            score += 2.0
        
        if any(term in snippet for term in ['password', 'secret', 'key', 'token']):
            score += 3.0
            
        return min(score, 10.0)  # Cap at 10

def init_logging(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "information_disclosure.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

def construir_query_avanzada(dominio: str, extension: str, categoria: str, *, subdomains=False) -> str:
    """Construye queries optimizadas para information disclosure"""
    site_part = f"site:*.{dominio}" if subdomains else f"site:{dominio}"
    
    if extension:
        ext_part = f"filetype:{extension}"
    else:
        ext_part = ""
    
    keywords = SENSITIVE_KEYWORDS.get(categoria, ["password", "secret"])
    
    # Construir query más agresiva
    keyword_queries = []
    for keyword in keywords[:3]:  # Limitar para evitar queries muy largas
        keyword_queries.append(f'intext:"{keyword}"')
        keyword_queries.append(f'intitle:"{keyword}"')
        keyword_queries.append(f'inurl:"{keyword}"')
    
    query_parts = [site_part]
    if ext_part:
        query_parts.append(ext_part)
    query_parts.append(f"({' OR '.join(keyword_queries)})")
    
    return " ".join(query_parts)

def analizar_contenido_sensible(url: str, content: str) -> Dict[str, Any]:
    """Analiza el contenido en busca de información sensible"""
    findings = {
        "sensitive_patterns": [],
        "severity": "low",
        "details": []
    }
    
    for pattern in HIGH_PRIORITY_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings["sensitive_patterns"].extend(matches)
            findings["severity"] = "high"
            findings["details"].append(f"Found sensitive pattern: {pattern}")
    
    # Buscar otros indicadores
    sensitive_terms = ["password", "secret", "api_key", "private_key", "token"]
    found_terms = [term for term in sensitive_terms if term in content.lower()]
    
    if found_terms:
        findings["details"].extend([f"Found term: {term}" for term in found_terms])
        if findings["severity"] == "low":
            findings["severity"] = "medium"
    
    return findings

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=2, max=30),
       retry=retry_if_exception_type(requests.exceptions.RequestException) | retry_if_result(lambda r: r is None))
def consultar_serpapi(api_key: str, query: str, start: int) -> Dict[str, Any] | None:
    params = {"q": query, "api_key": api_key, "engine": "google", "num": 20, "start": start}
    resp = requests.get(API_URL, params=params, timeout=30)
    if resp.status_code == 429 or resp.headers.get("X-RateLimit-Remaining") == "0":
        retry_after = int(resp.headers.get("Retry-After", "60"))
        logging.warning("Rate limit alcanzado. Esperando %s segundos...", retry_after)
        time.sleep(retry_after)
        raise requests.exceptions.HTTPError("429 Too Many Requests")
    resp.raise_for_status()
    return resp.json()

def descargar_y_analizar(url: str, out_dir: Path) -> Dict[str, Any]:
    """Descarga archivo y analiza contenido sensible"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        resp = requests.get(url, headers=headers, timeout=10, stream=True)
        resp.raise_for_status()
        
        # Limitar tamaño de descarga (10MB max)
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > 10 * 1024 * 1024:  # 10MB limit
                break
        
        # Intentar decodificar contenido
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = content.decode('latin-1', errors='ignore')
        
        # Analizar contenido
        analysis = analizar_contenido_sensible(url, text_content)
        
        # Guardar archivo si es sensible
        if analysis["severity"] in ["medium", "high"]:
            filename = hashlib.md5(url.encode()).hexdigest()[:12]
            file_path = out_dir / "downloaded_files" / f"{filename}.txt"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Analysis: {analysis}\n")
                f.write("="*80 + "\n")
                f.write(text_content[:5000])  # Primeros 5KB
            
            analysis["local_file"] = str(file_path)
        
        return analysis
        
    except Exception as e:
        logging.warning("Error descargando %s: %s", url, e)
        return {"error": str(e), "severity": "unknown"}

def tomar_screenshot_avanzado(url: str, output_path: Path) -> bool:
    """Screenshot con configuración optimizada para pentesting"""
    driver = None
    try:
        options = Options()
        options.headless = True
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--ignore-ssl-errors=yes')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--allow-running-insecure-content')
        options.add_argument('--window-size=1920,1080')
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(3)  # Tiempo para cargar contenido dinámico
        
        driver.save_screenshot(str(output_path))
        return True
        
    except Exception as e:
        logging.warning("No se pudo capturar %s: %s", url, e)
        return False
    finally:
        if driver:
            driver.quit()

def google_dorking_enhanced(*, api_key: str, dominio: str, categoria: str, pages: int, subdomains: bool, sleep_between: float, out_dir: Path) -> List[Dict[str, Any]]:
    """Version mejorada del dorking con análisis de sensibilidad"""
    results = []
    links_seen: Set[str] = set()
    screenshots_dir = out_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    # Procesar por extensión y sin extensión
    extensions_to_try = CRITICAL_EXTENSIONS[:8] + [None]  # Incluir búsqueda sin extensión
    
    for extension in extensions_to_try:
        query = construir_query_avanzada(dominio, extension, categoria, subdomains=subdomains)
        logging.info("Query: %s", query)
        
        for page in range(pages):
            start = page * 20
            try:
                data = consultar_serpapi(api_key, query, start)
                organic = data.get("organic_results", [])
                
                if not organic:
                    logging.info("Sin resultados en página %d para %s", page + 1, extension or "general")
                    break

                for r in organic:
                    link = r.get("link")
                    if link and link not in links_seen:
                        links_seen.add(link)
                        
                        # Crear resultado base
                        result = {k: r.get(k) for k in ["title", "link", "snippet", "position"]}
                        
                        # Calcular score de sensibilidad
                        sensitivity_score = SensitivityScorer.score_result(result)
                        result["sensitivity_score"] = sensitivity_score
                        result["extension"] = extension
                        result["categoria"] = categoria
                        
                        # Solo procesar resultados con score alto
                        if sensitivity_score >= 3.0:
                            # Screenshot
                            shot_path = screenshots_dir / f"{hashlib.md5(link.encode()).hexdigest()[:12]}.png"
                            if tomar_screenshot_avanzado(link, shot_path):
                                result["screenshot"] = str(shot_path.relative_to(out_dir))
                            
                            # Análisis de contenido para resultados muy sensibles
                            if sensitivity_score >= 6.0:
                                content_analysis = descargar_y_analizar(link, out_dir)
                                result["content_analysis"] = content_analysis
                        
                        results.append(result)
                        
                time.sleep(sleep_between)
                
            except Exception as e:
                logging.error("Error en %s [%s], página %d: %s", dominio, extension, page + 1, e)

    return sorted(results, key=lambda x: x.get("sensitivity_score", 0), reverse=True)

def generar_reporte_html(resultados: List[Dict[str, Any]], out_dir: Path) -> None:
    """Genera reporte HTML para análisis visual"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Information Disclosure Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .high-risk { background-color: #ffebee; border-left: 4px solid #f44336; }
            .medium-risk { background-color: #fff3e0; border-left: 4px solid #ff9800; }
            .low-risk { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
            .result-item { margin: 15px 0; padding: 15px; border-radius: 4px; }
            .score { font-weight: bold; font-size: 1.2em; }
            .screenshot { max-width: 300px; margin: 10px 0; }
            .details { margin: 10px 0; font-size: 0.9em; color: #666; }
        </style>
    </head>
    <body>
        <h1>Information Disclosure Report</h1>
        <h2>Total Results: {total}</h2>
    """.format(total=len(resultados))
    
    for result in resultados:
        score = result.get("sensitivity_score", 0)
        risk_class = "high-risk" if score >= 7 else "medium-risk" if score >= 4 else "low-risk"
        
        html_content += f"""
        <div class="result-item {risk_class}">
            <div class="score">Sensitivity Score: {score:.1f}/10</div>
            <h3><a href="{result.get('link', '')}" target="_blank">{result.get('title', 'N/A')}</a></h3>
            <p>{result.get('snippet', '')}</p>
            <div class="details">
                <strong>Extension:</strong> {result.get('extension', 'N/A')}<br>
                <strong>Category:</strong> {result.get('categoria', 'N/A')}
            </div>
        """
        
        if result.get('screenshot'):
            html_content += f'<img src="{result["screenshot"]}" class="screenshot" alt="Screenshot">'
        
        if result.get('content_analysis'):
            analysis = result['content_analysis']
            html_content += f"""
            <div class="content-analysis">
                <strong>Content Analysis:</strong> {analysis.get('severity', 'unknown')} severity<br>
                <strong>Details:</strong> {', '.join(analysis.get('details', []))}
            </div>
            """
        
        html_content += "</div>"
    
    html_content += "</body></html>"
    
    html_path = out_dir / "disclosure_report.html"
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logging.info("[HTML] Reporte generado: %s", html_path)

def main() -> None:
    parser = argparse.ArgumentParser(description="Information Disclosure Hunter - Optimizado para Pentesting/Red Team")
    parser.add_argument("-i", "--input", required=True, help="Dominio o archivo de dominios")
    parser.add_argument("-f", "--file", action="store_true", help="Indica que el input es un archivo")
    parser.add_argument("-c", "--categories", default="credentials,api_secrets,config,database", 
                       help="Categorías separadas por coma")
    parser.add_argument("-p", "--pages", type=int, default=2, help="Número de páginas por categoría")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Buscar en subdominios")
    parser.add_argument("-w", "--workers", type=int, default=3, help="Número de hilos en paralelo")
    parser.add_argument("-o", "--outdir", default="disclosure_results", help="Directorio de salida")
    parser.add_argument("--sleep", type=float, default=2.0, help="Delay entre peticiones (segundos)")
    parser.add_argument("--min-score", type=float, default=3.0, help="Score mínimo de sensibilidad")
    args = parser.parse_args()

    api_key = os.getenv("SERPAPI_KEY")
    if not api_key:
        sys.exit("ERROR: No se encontró la variable de entorno SERPAPI_KEY.")

    out_dir = Path(args.outdir)
    init_logging(out_dir)

    categorias = [c.strip() for c in args.categories.split(",") if c.strip()]
    dominios = []
    
    if args.file:
        with open(args.input, 'r') as f:
            dominios = [line.strip() for line in f if line.strip()]
    else:
        dominios = [args.input]

    all_results = []
    
    for dominio in dominios:
        logging.info("==> Analizando dominio: %s", dominio)
        
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = []
            for categoria in categorias:
                future = executor.submit(
                    google_dorking_enhanced,
                    api_key=api_key,
                    dominio=dominio,
                    categoria=categoria,
                    pages=args.pages,
                    subdomains=args.subdomains,
                    sleep_between=args.sleep,
                    out_dir=out_dir
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    # Filtrar por score mínimo
                    filtered_results = [r for r in results if r.get("sensitivity_score", 0) >= args.min_score]
                    all_results.extend(filtered_results)
                except Exception as e:
                    logging.error("Error procesando: %s", e)

    if all_results:
        # Ordenar por score de sensibilidad
        all_results.sort(key=lambda x: x.get("sensitivity_score", 0), reverse=True)
        
        # Guardar resultados
        json_path = out_dir / "information_disclosure.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        # Generar reporte HTML
        generar_reporte_html(all_results, out_dir)
        
        # Resumen por terminal
        high_risk = [r for r in all_results if r.get("sensitivity_score", 0) >= 7]
        medium_risk = [r for r in all_results if 4 <= r.get("sensitivity_score", 0) < 7]
        
        logging.info("="*60)
        logging.info("RESUMEN DE INFORMATION DISCLOSURE")
        logging.info("="*60)
        logging.info("🔴 Alto riesgo: %d resultados", len(high_risk))
        logging.info("🟡 Riesgo medio: %d resultados", len(medium_risk))
        logging.info("📊 Total encontrado: %d resultados", len(all_results))
        logging.info("📁 Resultados guardados en: %s", json_path)
        
        # Top 5 más críticos
        logging.info("\n🎯 TOP 5 MÁS CRÍTICOS:")
        for i, result in enumerate(all_results[:5], 1):
            logging.info("%d. [%.1f] %s", i, result.get("sensitivity_score", 0), result.get("link", ""))
        
    else:
        logging.info("[-] No se encontraron resultados con information disclosure.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Interrumpido por el usuario.")
