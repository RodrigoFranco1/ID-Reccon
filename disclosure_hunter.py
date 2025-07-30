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

# Enhanced terminal output with colors and formatting
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.columns import Columns
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Fallback colors for systems without rich
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# =====================================================================================
# CONFIGURACIONES OPTIMIZADAS PARA INFORMATION DISCLOSURE - PENTESTING/RED TEAM
# =====================================================================================

# Extensiones críticas para Information Disclosure
CRITICAL_EXTENSIONS = [
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
    "env", "config", "ini", "conf", "cfg", "properties", "yaml", "yml",
    "js", "php", "asp", "aspx", "jsp", "py", "rb", "go", "java",
    "bak", "backup", "old", "log", "tmp", "temp", "swp",
    "sql", "db", "sqlite", "mdb", "dump",
    "json", "xml", "csv",
    "key", "pem", "crt", "p12", "pfx", "jks"
]

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

class EnhancedConsole:
    """Enhanced console output handler with fallback support"""
    
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()
            self.use_rich = True
        else:
            self.use_rich = False
    
    def print_banner(self):
        """Print application banner"""
        if self.use_rich:
            banner = """
[bold red]╔══════════════════════════════════════════════════════════════════════════════╗[/]
[bold red]║[/] [bold cyan]Information Disclosure Hunter v2.0[/] [bold red]                                   ║[/]
[bold red]║[/] [yellow]🎯 Advanced Google Dorking for Pentesting & Red Team[/] [bold red]                    ║[/]
[bold red]║[/] [green]Optimized for finding sensitive data exposure[/] [bold red]                          ║[/]
[bold red]╚══════════════════════════════════════════════════════════════════════════════╝[/]
            """
            self.console.print(banner)
        else:
            print(f"""{Colors.RED}{'='*80}{Colors.END}
{Colors.CYAN}{Colors.BOLD}🎯 Information Disclosure Hunter v2.0{Colors.END}
{Colors.YELLOW}Advanced Google Dorking for Pentesting & Red Team{Colors.END}
{Colors.GREEN}Optimized for finding sensitive data exposure{Colors.END}
{Colors.RED}{'='*80}{Colors.END}""")
    
    def print_target_info(self, domains: List[str], categories: List[str]):
        """Print scan target information"""
        if self.use_rich:
            table = Table(title="🎯 Scan Configuration", box=box.ROUNDED)
            table.add_column("Parameter", style="cyan", no_wrap=True)
            table.add_column("Value", style="white")
            
            table.add_row("🌐 Target(s)", ", ".join(domains))
            table.add_row("📁 Categories", ", ".join(categories))
            table.add_row("🔍 Extensions", f"{len(CRITICAL_EXTENSIONS)} critical file types")
            
            self.console.print(table)
        else:
            print(f"\n{Colors.CYAN}🎯 Scan Configuration:{Colors.END}")
            print(f"  🌐 Target(s): {Colors.WHITE}{', '.join(domains)}{Colors.END}")
            print(f"  📁 Categories: {Colors.WHITE}{', '.join(categories)}{Colors.END}")
            print(f"  🔍 Extensions: {Colors.WHITE}{len(CRITICAL_EXTENSIONS)} critical file types{Colors.END}")
    
    def print_query_info(self, query: str, extension: str, categoria: str):
        """Print current query being executed"""
        if self.use_rich:
            self.console.print(f"[dim]🔍 Searching:[/] [yellow]{extension or 'general'}[/] [dim]|[/] [blue]{categoria}[/]")
        else:
            print(f"{Colors.YELLOW}🔍 Searching: {extension or 'general'} | {categoria}{Colors.END}")
    
    def print_no_results(self, extension: str, page: int):
        """Print no results message"""
        if self.use_rich:
            self.console.print(f"[dim]  ❌ No results for {extension} on page {page}[/]")
        else:
            print(f"  ❌ No results for {extension} on page {page}")
    
    def print_finding(self, result: Dict[str, Any], index: int):
        """Print individual finding with enhanced formatting"""
        score = result.get("sensitivity_score", 0)
        title = result.get("title", "N/A")[:70] + "..." if len(result.get("title", "")) > 70 else result.get("title", "N/A")
        link = result.get("link", "N/A")
        extension = result.get("extension", "N/A")
        
        # Risk level emoji and color
        if score >= 7.0:
            risk_emoji = "🔴"
            risk_color = "red" if self.use_rich else Colors.RED
        elif score >= 4.0:
            risk_emoji = "🟡"
            risk_color = "yellow" if self.use_rich else Colors.YELLOW
        else:
            risk_emoji = "🟢"
            risk_color = "green" if self.use_rich else Colors.GREEN
        
        if self.use_rich:
            self.console.print(f"[bold {risk_color}]{risk_emoji} [{score:.1f}/10][/] [white]{title}[/]")
            self.console.print(f"    [dim]📁 {extension} | 🔗[/] [blue]{link}[/]")
            if result.get("content_analysis"):
                analysis = result["content_analysis"]
                self.console.print(f"    [bold red]⚠️  Content Analysis: {analysis.get('severity', 'unknown').upper()}[/]")
        else:
            print(f"{risk_color}{risk_emoji} [{score:.1f}/10] {title}{Colors.END}")
            print(f"    📁 {extension} | 🔗 {link}")
            if result.get("content_analysis"):
                analysis = result["content_analysis"]
                print(f"    {Colors.RED}⚠️  Content Analysis: {analysis.get('severity', 'unknown').upper()}{Colors.END}")
    
    def print_summary(self, results: List[Dict[str, Any]]):
        """Print final summary with statistics"""
        high_risk = [r for r in results if r.get("sensitivity_score", 0) >= 7]
        medium_risk = [r for r in results if 4 <= r.get("sensitivity_score", 0) < 7]
        low_risk = [r for r in results if r.get("sensitivity_score", 0) < 4]
        
        if self.use_rich:
            # Create summary table
            summary_table = Table(title="📊 Scan Results Summary", box=box.DOUBLE_EDGE)
            summary_table.add_column("Risk Level", style="bold", no_wrap=True)
            summary_table.add_column("Count", justify="center", style="bold")
            summary_table.add_column("Percentage", justify="center")
            
            total = len(results)
            if total > 0:
                summary_table.add_row("🔴 Critical (7.0-10.0)", str(len(high_risk)), f"{len(high_risk)/total*100:.1f}%")
                summary_table.add_row("🟡 Medium (4.0-6.9)", str(len(medium_risk)), f"{len(medium_risk)/total*100:.1f}%")
                summary_table.add_row("🟢 Low (0.0-3.9)", str(len(low_risk)), f"{len(low_risk)/total*100:.1f}%")
                summary_table.add_row("[bold]Total", f"[bold]{total}", "100.0%")
            
            self.console.print(summary_table)
            
            # Top findings
            if results:
                self.console.print("\n[bold cyan]🏆 Top 5 Critical Findings:[/]")
                for i, result in enumerate(results[:5], 1):
                    score = result.get("sensitivity_score", 0)
                    title = result.get("title", "N/A")[:60]
                    risk_emoji = "🔴" if score >= 7 else "🟡" if score >= 4 else "🟢"
                    self.console.print(f"  {i}. {risk_emoji} [bold red][{score:.1f}][/] [white]{title}[/]")
        else:
            print(f"\n{Colors.CYAN}📊 Scan Results Summary:{Colors.END}")
            print(f"  🔴 Critical (7.0-10.0): {Colors.RED}{len(high_risk)}{Colors.END}")
            print(f"  🟡 Medium (4.0-6.9): {Colors.YELLOW}{len(medium_risk)}{Colors.END}")
            print(f"  🟢 Low (0.0-3.9): {Colors.GREEN}{len(low_risk)}{Colors.END}")
            print(f"  📊 Total: {Colors.WHITE}{len(results)}{Colors.END}")
            
            if results:
                print(f"\n{Colors.CYAN}🏆 Top 5 Critical Findings:{Colors.END}")
                for i, result in enumerate(results[:5], 1):
                    score = result.get("sensitivity_score", 0)
                    title = result.get("title", "N/A")[:60]
                    risk_color = Colors.RED if score >= 7 else Colors.YELLOW if score >= 4 else Colors.GREEN
                    print(f"  {i}. {risk_color}[{score:.1f}] {title}{Colors.END}")
    
    def print_progress_start(self, total_tasks: int):
        """Initialize progress tracking"""
        if self.use_rich:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                console=self.console
            )
            self.task = self.progress.add_task("Scanning...", total=total_tasks)
            self.progress.start()
        else:
            print(f"{Colors.CYAN}🚀 Starting scan with {total_tasks} tasks...{Colors.END}")
            self.current_task = 0
            self.total_tasks = total_tasks
    
    def update_progress(self, description: str = None):
        """Update progress"""
        if self.use_rich and hasattr(self, 'progress'):
            if description:
                self.progress.update(self.task, description=description, advance=1)
            else:
                self.progress.advance(self.task)
        else:
            self.current_task += 1
            percent = (self.current_task / self.total_tasks) * 100
            print(f"{Colors.BLUE}📊 Progress: {percent:.1f}% ({self.current_task}/{self.total_tasks}){Colors.END}")
    
    def finish_progress(self):
        """Finish progress tracking"""
        if self.use_rich and hasattr(self, 'progress'):
            self.progress.stop()

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
        for ext in CRITICAL_EXTENSIONS[:10]:
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
            
        return min(score, 10.0)

def sanitize_domain_name(domain: str) -> str:
    """Sanitiza el nombre del dominio para usarlo como nombre de directorio"""
    # Remover protocolo si existe
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1]
    
    # Remover puerto si existe
    if ':' in domain:
        domain = domain.split(':', 1)[0]
    
    # Remover path si existe
    if '/' in domain:
        domain = domain.split('/', 1)[0]
    
    # Reemplazar caracteres no válidos para nombres de directorio
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        domain = domain.replace(char, '_')
    
    # Remover puntos del final y espacios
    domain = domain.strip('. ')
    
    return domain if domain else "unknown_domain"

def create_domain_directory(base_dir: Path, domain: str) -> Path:
    """Crea directorio específico para el dominio y subdirectorios necesarios"""
    sanitized_domain = sanitize_domain_name(domain)
    domain_dir = base_dir / sanitized_domain
    
    # Crear estructura de directorios
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "screenshots").mkdir(exist_ok=True)
    (domain_dir / "downloaded_files").mkdir(exist_ok=True)
    
    return domain_dir
    """Initialize logging with enhanced console output"""
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "information_disclosure.log"

    # Create custom formatter that doesn't interfere with rich output
    file_formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(file_formatter)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    
    # Disable console handler to avoid interference with rich output
    logger.propagate = False

def construir_query_avanzada(dominio: str, extension: str, categoria: str, *, subdomains=False) -> str:
    """Construye queries optimizadas para information disclosure"""
    site_part = f"site:*.{dominio}" if subdomains else f"site:{dominio}"
    
    if extension:
        ext_part = f"filetype:{extension}"
    else:
        ext_part = ""
    
    keywords = SENSITIVE_KEYWORDS.get(categoria, ["password", "secret"])
    
    keyword_queries = []
    for keyword in keywords[:3]:
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
        time.sleep(retry_after)
        raise requests.exceptions.HTTPError("429 Too Many Requests")
    resp.raise_for_status()
    return resp.json()

def descargar_y_analizar(url: str, domain_dir: Path) -> Dict[str, Any]:
    """Descarga archivo y analiza contenido sensible en directorio específico del dominio"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        resp = requests.get(url, headers=headers, timeout=10, stream=True)
        resp.raise_for_status()
        
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > 10 * 1024 * 1024:  # 10MB limit
                break
        
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = content.decode('latin-1', errors='ignore')
        
        analysis = analizar_contenido_sensible(url, text_content)
        
        if analysis["severity"] in ["medium", "high"]:
            filename = hashlib.md5(url.encode()).hexdigest()[:12]
            file_path = domain_dir / "downloaded_files" / f"{filename}.txt"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Analysis: {analysis}\n")
                f.write("="*80 + "\n")
                f.write(text_content[:5000])  # Primeros 5KB
            
            analysis["local_file"] = str(file_path.relative_to(domain_dir))
        
        return analysis
        
    except Exception as e:
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
        time.sleep(3)
        
        driver.save_screenshot(str(output_path))
        return True
        
    except Exception as e:
        return False
    finally:
        if driver:
            driver.quit()

def google_dorking_enhanced(*, api_key: str, dominio: str, categoria: str, pages: int, subdomains: bool, sleep_between: float, domain_dir: Path, console: EnhancedConsole) -> List[Dict[str, Any]]:
    """Version mejorada del dorking con output embellecido y directorio específico por dominio"""
    results = []
    links_seen: Set[str] = set()
    screenshots_dir = domain_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    extensions_to_try = CRITICAL_EXTENSIONS[:8] + [None]
    
    for extension in extensions_to_try:
        query = construir_query_avanzada(dominio, extension, categoria, subdomains=subdomains)
        console.print_query_info(query, extension, categoria)
        
        for page in range(pages):
            start = page * 20
            try:
                data = consultar_serpapi(api_key, query, start)
                organic = data.get("organic_results", [])
                
                if not organic:
                    console.print_no_results(extension or "general", page + 1)
                    break

                for r in organic:
                    link = r.get("link")
                    if link and link not in links_seen:
                        links_seen.add(link)
                        
                        result = {k: r.get(k) for k in ["title", "link", "snippet", "position"]}
                        
                        sensitivity_score = SensitivityScorer.score_result(result)
                        result["sensitivity_score"] = sensitivity_score
                        result["extension"] = extension
                        result["categoria"] = categoria
                        result["domain"] = dominio
                        
                        if sensitivity_score >= 3.0:
                            console.print_finding(result, len(results) + 1)
                            
                            shot_path = screenshots_dir / f"{hashlib.md5(link.encode()).hexdigest()[:12]}.png"
                            if tomar_screenshot_avanzado(link, shot_path):
                                result["screenshot"] = str(shot_path.relative_to(domain_dir))
                            
                            if sensitivity_score >= 6.0:
                                content_analysis = descargar_y_analizar(link, domain_dir)
                                result["content_analysis"] = content_analysis
                        
                        results.append(result)
                        console.update_progress()
                        
                time.sleep(sleep_between)
                
            except Exception as e:
                pass  # Error logging handled silently

    return sorted(results, key=lambda x: x.get("sensitivity_score", 0), reverse=True)

def generar_reporte_html(resultados: List[Dict[str, Any]], domain_dir: Path, domain: str) -> None:
    """Genera reporte HTML para análisis visual en directorio específico del dominio"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Information Disclosure Report - {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
            .domain-info {{ background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .high-risk {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
            .medium-risk {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
            .low-risk {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
            .result-item {{ margin: 15px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); background: white; }}
            .score {{ font-weight: bold; font-size: 1.2em; display: inline-block; padding: 5px 10px; border-radius: 4px; color: white; }}
            .score.high {{ background-color: #f44336; }}
            .score.medium {{ background-color: #ff9800; }}
            .score.low {{ background-color: #4caf50; }}
            .screenshot {{ max-width: 300px; margin: 10px 0; border-radius: 4px; }}
            .details {{ margin: 10px 0; font-size: 0.9em; color: #666; }}
            .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .timestamp {{ color: #888; font-size: 0.9em; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎯 Information Disclosure Report</h1>
            <p>Advanced Google Dorking Results for: <strong>{domain}</strong></p>
            <p class="timestamp">Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="domain-info">
            <h3>🌐 Target Domain: {domain}</h3>
            <p><strong>Scan Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Results:</strong> {len(resultados)}</p>
        </div>
    """
    
    # Add statistics
    high_risk = [r for r in resultados if r.get("sensitivity_score", 0) >= 7]
    medium_risk = [r for r in resultados if 4 <= r.get("sensitivity_score", 0) < 7]
    low_risk = [r for r in resultados if r.get("sensitivity_score", 0) < 4]
    
    html_content += f"""
        <div class="stats">
            <div class="stat-card">
                <h3 style="color: #f44336;">🔴 Critical</h3>
                <h2>{len(high_risk)}</h2>
                <p>High Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #ff9800;">🟡 Medium</h3>
                <h2>{len(medium_risk)}</h2>
                <p>Medium Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #4caf50;">🟢 Low</h3>
                <h2>{len(low_risk)}</h2>
                <p>Low Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #2196f3;">📊 Total</h3>
                <h2>{len(resultados)}</h2>
                <p>Total Results</p>
            </div>
        </div>
    """
    
    for result in resultados:
        score = result.get("sensitivity_score", 0)
        risk_class = "high-risk" if score >= 7 else "medium-risk" if score >= 4 else "low-risk"
        score_class = "high" if score >= 7 else "medium" if score >= 4 else "low"
        
        html_content += f"""
        <div class="result-item {risk_class}">
            <span class="score {score_class}">{score:.1f}/10</span>
            <h3><a href="{result.get('link', '')}" target="_blank">{result.get('title', 'N/A')}</a></h3>
            <p>{result.get('snippet', '')}</p>
            <div class="details">
                <strong>📁 Extension:</strong> {result.get('extension', 'N/A')}<br>
                <strong>🏷️ Category:</strong> {result.get('categoria', 'N/A')}<br>
                <strong>🌐 Domain:</strong> {result.get('domain', 'N/A')}
            </div>
        """
        
        if result.get('screenshot'):
            html_content += f'<img src="{result["screenshot"]}" class="screenshot" alt="Screenshot">'
        
        if result.get('content_analysis'):
            analysis = result['content_analysis']
            severity_color = "#f44336" if analysis.get('severity') == 'high' else "#ff9800" if analysis.get('severity') == 'medium' else "#4caf50"
            html_content += f"""
            <div class="content-analysis" style="background-color: {severity_color}20; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong style="color: {severity_color};">⚠️ Content Analysis:</strong> {analysis.get('severity', 'unknown').upper()} severity<br>
                <strong>Details:</strong> {', '.join(analysis.get('details', []))}
            </div>
            """
        
        html_content += "</div>"
    
    html_content += """
        </body>
        </html>
    """
    
    html_path = domain_dir / "disclosure_report.html"
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_path
    
    # Add statistics
    high_risk = [r for r in resultados if r.get("sensitivity_score", 0) >= 7]
    medium_risk = [r for r in resultados if 4 <= r.get("sensitivity_score", 0) < 7]
    low_risk = [r for r in resultados if r.get("sensitivity_score", 0) < 4]
    
    html_content += f"""
        <div class="stats">
            <div class="stat-card">
                <h3 style="color: #f44336;">🔴 Critical</h3>
                <h2>{len(high_risk)}</h2>
                <p>High Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #ff9800;">🟡 Medium</h3>
                <h2>{len(medium_risk)}</h2>
                <p>Medium Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #4caf50;">🟢 Low</h3>
                <h2>{len(low_risk)}</h2>
                <p>Low Risk Findings</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #2196f3;">📊 Total</h3>
                <h2>{len(resultados)}</h2>
                <p>Total Results</p>
            </div>
        </div>
    """
    
    for result in resultados:
        score = result.get("sensitivity_score", 0)
        risk_class = "high-risk" if score >= 7 else "medium-risk" if score >= 4 else "low-risk"
        score_class = "high" if score >= 7 else "medium" if score >= 4 else "low"
        
        html_content += f"""
        <div class="result-item {risk_class}">
            <span class="score {score_class}">{score:.1f}/10</span>
            <h3><a href="{result.get('link', '')}" target="_blank">{result.get('title', 'N/A')}</a></h3>
            <p>{result.get('snippet', '')}</p>
            <div class="details">
                <strong>📁 Extension:</strong> {result.get('extension', 'N/A')}<br>
                <strong>🏷️ Category:</strong> {result.get('categoria', 'N/A')}
            </div>
        """
        
        if result.get('screenshot'):
            html_content += f'<img src="{result["screenshot"]}" class="screenshot" alt="Screenshot">'
        
        if result.get('content_analysis'):
            analysis = result['content_analysis']
            severity_color = "#f44336" if analysis.get('severity') == 'high' else "#ff9800" if analysis.get('severity') == 'medium' else "#4caf50"
            html_content += f"""
            <div class="content-analysis" style="background-color: {severity_color}20; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <strong style="color: {severity_color};">⚠️ Content Analysis:</strong> {analysis.get('severity', 'unknown').upper()} severity<br>
                <strong>Details:</strong> {', '.join(analysis.get('details', []))}
            </div>
            """
        
        html_content += "</div>"
    
    html_content += """
        </body>
        </html>
    """
    
    html_path = out_dir / "disclosure_report.html"
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def main() -> None:
    parser = argparse.ArgumentParser(description="Information Disclosure Hunter - Enhanced Output Version")
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
    parser.add_argument("--no-banner", action="store_true", help="Ocultar banner de inicio")
    parser.add_argument("--simple-output", action="store_true", help="Usar output simple sin rich")
    args = parser.parse_args()

    # Initialize enhanced console
    console = EnhancedConsole()
    
    # Override rich if requested
    if args.simple_output:
        console.use_rich = False

    api_key = os.getenv("SERPAPI_KEY")
    if not api_key:
        if console.use_rich:
            console.console.print("[bold red]❌ ERROR: No se encontró la variable de entorno SERPAPI_KEY.[/]")
        else:
            print(f"{Colors.RED}❌ ERROR: No se encontró la variable de entorno SERPAPI_KEY.{Colors.END}")
        sys.exit(1)

    # Print banner
    if not args.no_banner:
        console.print_banner()

    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    categorias = [c.strip() for c in args.categories.split(",") if c.strip()]
    dominios = []
    
    if args.file:
        try:
            with open(args.input, 'r') as f:
                dominios = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            if console.use_rich:
                console.console.print(f"[bold red]❌ Error: No se pudo encontrar el archivo {args.input}[/]")
            else:
                print(f"{Colors.RED}❌ Error: No se pudo encontrar el archivo {args.input}{Colors.END}")
            sys.exit(1)
    else:
        dominios = [args.input]

    # Print scan configuration
    console.print_target_info(dominios, categorias)

    # Calculate total tasks for progress tracking
    total_tasks = len(dominios) * len(categorias) * len(CRITICAL_EXTENSIONS[:8] + [None]) * args.pages
    console.print_progress_start(total_tasks)

    # Dictionary to store results by domain
    domain_results = {}
    
    for dominio in dominios:
        if console.use_rich:
            console.console.print(f"\n[bold cyan]🎯 Analyzing domain:[/] [white]{dominio}[/]")
        else:
            print(f"\n{Colors.CYAN}🎯 Analyzing domain: {Colors.WHITE}{dominio}{Colors.END}")
        
        # Create domain-specific directory and initialize logging
        domain_dir = init_enhanced_logging(out_dir, dominio, console)
        domain_results[dominio] = {"results": [], "domain_dir": domain_dir}
        
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
                    domain_dir=domain_dir,
                    console=console
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    filtered_results = [r for r in results if r.get("sensitivity_score", 0) >= args.min_score]
                    domain_results[dominio]["results"].extend(filtered_results)
                except Exception as e:
                    if console.use_rich:
                        console.console.print(f"[red]❌ Error procesando: {str(e)}[/]")
                    else:
                        print(f"{Colors.RED}❌ Error procesando: {str(e)}{Colors.END}")

    # Finish progress tracking
    console.finish_progress()

    # Process results for each domain
    all_results = []
    for dominio, data in domain_results.items():
        results = data["results"]
        domain_dir = data["domain_dir"]
        
        if results:
            # Sort by sensitivity score
            results.sort(key=lambda x: x.get("sensitivity_score", 0), reverse=True)
            all_results.extend(results)
            
            # Save domain-specific JSON
            json_path = domain_dir / "information_disclosure.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            # Generate domain-specific HTML report
            html_path = generar_reporte_html(results, domain_dir, dominio)
            
            # Print domain summary
            high_risk = [r for r in results if r.get("sensitivity_score", 0) >= 7]
            medium_risk = [r for r in results if 4 <= r.get("sensitivity_score", 0) < 7]
            low_risk = [r for r in results if r.get("sensitivity_score", 0) < 4]
            
            if console.use_rich:
                console.console.print(f"\n[bold green]📊 Results for {dominio}:[/]")
                console.console.print(f"  🔴 Critical: [red]{len(high_risk)}[/]")
                console.console.print(f"  🟡 Medium: [yellow]{len(medium_risk)}[/]")
                console.console.print(f"  🟢 Low: [green]{len(low_risk)}[/]")
                console.console.print(f"  📁 Saved to: [blue]{domain_dir}[/]")
            else:
                print(f"\n{Colors.GREEN}📊 Results for {dominio}:{Colors.END}")
                print(f"  🔴 Critical: {Colors.RED}{len(high_risk)}{Colors.END}")
                print(f"  🟡 Medium: {Colors.YELLOW}{len(medium_risk)}{Colors.END}")
                print(f"  🟢 Low: {Colors.GREEN}{len(low_risk)}{Colors.END}")
                print(f"  📁 Saved to: {domain_dir}")

    if all_results:
        # Sort all results by sensitivity score
        all_results.sort(key=lambda x: x.get("sensitivity_score", 0), reverse=True)
        
        # Create consolidated report
        consolidated_json = out_dir / "consolidated_results.json"
        with open(consolidated_json, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        # Print overall summary
        console.print_summary(all_results)
        
        # Print file locations
        if console.use_rich:
            console.console.print(f"\n[green]📁 Results organized by domain in:[/] [blue]{out_dir}[/]")
            console.console.print(f"📄 Consolidated JSON: [blue]{consolidated_json}[/]")
            console.console.print(f"\n[cyan]📂 Domain-specific directories:[/]")
            for dominio in dominios:
                sanitized = sanitize_domain_name(dominio)
                console.console.print(f"  🌐 {dominio}: [blue]{out_dir / sanitized}[/]")
        else:
            print(f"\n{Colors.GREEN}📁 Results organized by domain in: {Colors.BLUE}{out_dir}{Colors.END}")
            print(f"📄 Consolidated JSON: {consolidated_json}")
            print(f"\n{Colors.CYAN}📂 Domain-specific directories:{Colors.END}")
            for dominio in dominios:
                sanitized = sanitize_domain_name(dominio)
                print(f"  🌐 {dominio}: {out_dir / sanitized}")
        
    else:
        if console.use_rich:
            console.console.print("[yellow]⚠️ No se encontraron resultados con information disclosure.[/]")
        else:
            print(f"{Colors.YELLOW}⚠️ No se encontraron resultados con information disclosure.{Colors.END}")Colors.END}")
            print(f"  📄 JSON: {json_path}")
            print(f"  🌐 HTML Report: {out_dir / 'disclosure_report.html'}")
            print(f"  📸 Screenshots: {out_dir / 'screenshots'}")
            print(f"  📥 Downloaded files: {out_dir / 'downloaded_files'}")
        
    else:
        if console.use_rich:
            console.console.print("[yellow]⚠️ No se encontraron resultados con information disclosure.[/]")
        else:
            print(f"{Colors.YELLOW}⚠️ No se encontraron resultados con information disclosure.{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Interrumpido por el usuario.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error fatal: {str(e)}{Colors.END}")
        sys.exit(1)
