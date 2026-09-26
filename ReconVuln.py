#!/usr/bin/env python3
"""
ReconVuln - Reconocimiento y Correlación de Vulnerabilidades
==============================================================

Herramienta única que combina en un solo flujo:
  1. Enumeración de subdominios vía Certificate Transparency (crt.sh)
  2. Escaneo de puertos + detección de versión de servicio (banner grabbing)
  3. Correlación automática con la base de datos NVD (CVE) para las
     versiones detectadas -> identificación de vulnerabilidades conocidas
  4. Informe final ordenado por severidad (CVSS) + export a JSON

IMPORTANTE: Esta herramienta es de RECONOCIMIENTO Y DETECCIÓN, no de
explotación. No lanza ataques, no envía payloads de inyección ni
ejecuta exploits contra el objetivo — únicamente identifica qué
versiones de software corren en los puertos abiertos y comprueba si
esas versiones tienen CVEs publicados públicamente. Qué hacer con esa
información (parchear, reportar, investigar más) es decisión tuya.

USO ÉTICO Y LEGAL: usa esta herramienta únicamente sobre dominios,
IPs o sistemas de tu propiedad, o para los que tengas autorización
expresa por escrito. Escanear sistemas de terceros sin permiso es
ilegal en la mayoría de países.

Dependencias: pip install requests
Uso: python3 reconvuln.py ejemplo.com
"""

import socket
import ssl
import urllib.parse
import json
import re
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

TOP_PUERTOS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
               993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888,
               27017, 6379, 9200]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalizar_dominio(entrada):
    """Acepta tanto 'ejemplo.com' como 'https://ejemplo.com/algo' y
    devuelve siempre solo el dominio limpio."""
    entrada = entrada.strip()
    if "://" in entrada:
        entrada = urllib.parse.urlparse(entrada).netloc
    return entrada.rstrip("/")


def nombre_archivo_seguro(dominio):
    """Sustituye cualquier carácter no válido en nombres de archivo de
    Windows (: / \\ * ? " < > |) para evitar errores al guardar el informe."""
    return re.sub(r'[\\/:*?"<>|]', "_", dominio)


# ---------------------------------------------------------------------
# 1. Enumeración de subdominios (Certificate Transparency)
# ---------------------------------------------------------------------
def enumerar_subdominios(dominio):
    print(f"\n[*] Buscando subdominios de {dominio} en logs de Certificate Transparency...")
    subdominios = set()
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{dominio}&output=json", timeout=15)
        resp.raise_for_status()
        datos = resp.json()
        for entrada in datos:
            for nombre in entrada.get("name_value", "").split("\n"):
                nombre = nombre.strip().lower()
                if nombre and not nombre.startswith("*") and dominio in nombre:
                    subdominios.add(nombre)
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"    (no se pudo consultar crt.sh: {e})")
    subdominios.add(dominio)
    print(f"[+] {len(subdominios)} subdominios únicos encontrados.")
    return sorted(subdominios)


def resolver_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# ---------------------------------------------------------------------
# 2. Escaneo de puertos + banner grabbing
# ---------------------------------------------------------------------
def obtener_banner(ip, puerto, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, puerto)) != 0:
                return None
            try:
                if puerto in (443, 8443):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=ip) as ss:
                        ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        return ss.recv(1024).decode(errors="ignore").strip()
                if puerto in (80, 8080, 8000, 8888):
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                return s.recv(1024).decode(errors="ignore").strip()
            except Exception:
                return ""
    except socket.error:
        return None


def escanear_host(host):
    ip = resolver_host(host)
    if not ip:
        return None
    resultado = {"host": host, "ip": ip, "puertos": []}
    with ThreadPoolExecutor(max_workers=50) as executor:
        futuros = {executor.submit(obtener_banner, ip, p): p for p in TOP_PUERTOS}
        for futuro in as_completed(futuros):
            puerto = futuros[futuro]
            banner = futuro.result()
            if banner is not None:
                resultado["puertos"].append({"puerto": puerto, "banner": banner[:200]})
    return resultado if resultado["puertos"] else None


# ---------------------------------------------------------------------
# 3. Extraer producto/versión + correlación con NVD
# ---------------------------------------------------------------------
PATRON_SERVER = re.compile(
    r"^server:\s*([A-Za-z][A-Za-z0-9\-_]{2,30})[/ ]v?(\d+(?:\.\d+){1,3})",
    re.IGNORECASE | re.MULTILINE,
)


def extraer_producto_version(banner):
    """Extrae producto/versión SOLO de la cabecera 'Server:', nunca de la
    línea de estado HTTP (que empieza por 'HTTP/1.0' o 'HTTP/1.1' y no es
    software identificable, solo la versión del protocolo)."""
    m = PATRON_SERVER.search(banner)
    if not m:
        return None, None
    producto, version = m.group(1), m.group(2)
    if producto.lower() in ("http", "https"):
        return None, None
    return producto, version


def buscar_cves(producto, version):
    """Consulta la API pública del NVD para CVEs conocidos de un producto/versión."""
    try:
        params = {"keywordSearch": f"{producto} {version}", "resultsPerPage": 5}
        resp = requests.get(NVD_API, params=params, timeout=15,
                             headers={"User-Agent": "ReconVuln/1.0"})
        resp.raise_for_status()
        datos = resp.json()
    except (requests.RequestException, json.JSONDecodeError):
        return []

    cves = []
    for item in datos.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descripcion = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
        )
        # Filtro de relevancia: el nombre del producto debe aparecer
        # realmente en la descripción del CVE, si no, se descarta como ruido.
        if producto.lower() not in descripcion.lower():
            continue
        metricas = cve.get("metrics", {})
        score = None
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if clave in metricas:
                score = metricas[clave][0]["cvssData"]["baseScore"]
                break
        cves.append({"id": cve.get("id"), "score": score, "descripcion": descripcion[:180]})
    return cves


# ---------------------------------------------------------------------
# 4. Orquestación e informe
# ---------------------------------------------------------------------
def analizar_dominio(dominio, max_subdominios=15):
    subdominios = enumerar_subdominios(dominio)[:max_subdominios]

    print(f"\n[*] Escaneando puertos y detectando servicios en {len(subdominios)} hosts...")
    hallazgos = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futuros = [executor.submit(escanear_host, h) for h in subdominios]
        for futuro in as_completed(futuros):
            r = futuro.result()
            if r:
                hallazgos.append(r)
                print(f"    [+] {r['host']} ({r['ip']}) -> {len(r['puertos'])} puertos abiertos")

    print("\n[*] Correlacionando versiones de servicio con CVEs conocidos (NVD)...")
    informe = []
    for h in hallazgos:
        for p in h["puertos"]:
            producto, version = extraer_producto_version(p["banner"])
            entrada = {
                "host": h["host"], "ip": h["ip"], "puerto": p["puerto"],
                "banner": p["banner"], "producto": producto, "version": version,
                "cves": buscar_cves(producto, version) if producto and version else [],
            }
            informe.append(entrada)

    informe.sort(key=lambda e: max([c["score"] or 0 for c in e["cves"]], default=0), reverse=True)

    print("\n" + "=" * 70)
    print("INFORME FINAL")
    print("=" * 70)
    for e in informe:
        etiqueta = f"{e['producto']} {e['version']}" if e["producto"] else "servicio sin identificar"
        print(f"\n{e['host']} ({e['ip']}):{e['puerto']}  -  {etiqueta}")
        if e["cves"]:
            for c in e["cves"]:
                sev = f"CVSS {c['score']}" if c["score"] else "sin puntuación"
                print(f"    ⚠️  {c['id']} ({sev}): {c['descripcion']}")
        elif e["producto"]:
            print("    ✅ Sin CVEs conocidos encontrados para esta versión.")

    nombre_archivo = f"informe_{nombre_archivo_seguro(dominio)}_{datetime.now():%Y%m%d_%H%M%S}.json"
    try:
        with open(nombre_archivo, "w") as f:
            json.dump(informe, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Informe completo guardado en: {nombre_archivo}")
    except OSError as e:
        print(f"\n[!] No se pudo guardar el informe en disco ({e}).")
        print("    Esto no afecta al análisis de arriba, solo al archivo JSON exportado.")
        print("    Prueba a ejecutar el script desde otra carpeta, como el Escritorio,")
        print("    o revisa si tu antivirus está bloqueando la escritura de archivos.")


def main():
    parser = argparse.ArgumentParser(
        description="ReconVuln: reconocimiento + correlación de CVEs (solo detección, no explotación)."
    )
    parser.add_argument("dominio", nargs="?", default=None,
                         help="Dominio a analizar (ej: ejemplo.com). Si no se indica, se pedirá por teclado.")
    parser.add_argument("--max-subdominios", type=int, default=15,
                         help="Límite de subdominios a escanear (por defecto 15)")
    args = parser.parse_args()

    print("=" * 70)
    print("  RECONVULN — Reconocimiento y Correlación de Vulnerabilidades")
    print("  Uso ético: solo en dominios propios o con autorización expresa")
    print("=" * 70)

    dominio = args.dominio
    while not dominio:
        dominio = input("\nIntroduce el dominio a analizar (ej: ejemplo.com): ").strip()
    dominio = normalizar_dominio(dominio)

    analizar_dominio(dominio, args.max_subdominios)


if __name__ == "__main__":
    main()
