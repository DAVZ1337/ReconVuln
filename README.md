# ReconVuln
ReconVuln

Herramienta de reconocimiento y correlación de vulnerabilidades conocidas (CVE). Combina en un solo flujo:

Enumeración de subdominios vía Certificate Transparency (crt.sh)
Escaneo de puertos con detección de servicio (banner grabbing)
Correlación automática con el NVD (base de datos oficial de CVEs) para las versiones de software detectadas
Informe final ordenado por severidad (CVSS) + export a JSON

⚠️ Es una herramienta de detección, no de explotación. No lanza ataques ni ejecuta exploits — solo identifica qué corre en cada puerto y si esa versión tiene CVEs publicados.

Uso ético y legal

Usa esta herramienta únicamente sobre dominios, IPs o sistemas de tu propiedad, o para los que tengas autorización expresa por escrito. Escanear sistemas de terceros sin permiso puede ser ilegal.

Objetivos seguros para practicar:

scanme.nmap.org — servidor oficial de Nmap para practicar escaneos
localhost — tu propio equipo
Máquinas de laboratorio de TryHackMe / HackTheBox
Metasploitable2 (VM de práctica descargable)
Instalación

Requiere Python 3 y la librería requests:

bash
pip install requests
Uso
bash
python reconvuln.py ejemplo.com

También acepta una URL completa (se limpia automáticamente):

bash
python reconvuln.py https://ejemplo.com/algo

Opciones:

Parámetro	Descripción	Por defecto
dominio	Dominio o URL a analizar. Si no se indica, se pide por teclado	—
--max-subdominios	Límite de subdominios a escanear	15

Si lo ejecutas sin argumento, o si acabas de terminar un análisis, el script te pedirá un dominio directamente por teclado. Escribe salir (o exit / q) para cerrar el programa.

Salida
En pantalla: resumen de subdominios, puertos abiertos, servicio detectado y CVEs asociados (si los hay)
En disco: un archivo informe_<dominio>_<fecha>.json con todos los detalles
Solución de problemas
"the following arguments are required: dominio" → no pasaste ningún dominio al ejecutar. Es normal, simplemente escríbelo cuando te lo pida.
Error al guardar el informe (permisos, antivirus) → el script sigue funcionando igual, solo avisa que no pudo guardar el JSON. Prueba a ejecutarlo desde otra carpeta (ej. el Escritorio).
Proxy/firewall bloqueando conexiones → si estás en una red corporativa o con restricciones, puede que no llegue a crt.sh o a la API del NVD.
CVEs que no tienen sentido con lo que sabes del objetivo → puede pasar si el servidor no expone versión real (ej. Google solo responde Server: gws sin versión); en ese caso el script ya no debería asignarle ningún CVE.
Limitaciones
El escaneo de puertos cubre una lista de ~26 puertos comunes, no los 65535
La correlación con el NVD depende de que el banner del servicio incluya una versión reconocible; muchos servicios (como los de Google) no la exponen
No detecta vulnerabilidades de aplicación web (inyecciones, XSS, etc.) — solo vulnerabilidades conocidas asociadas a versiones de software de red
