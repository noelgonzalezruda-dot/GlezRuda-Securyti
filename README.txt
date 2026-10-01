GLEZRUDA SECURITY V1
====================

Requisitos para ejecutar desde codigo:
- Windows 10/11
- Python 3.10 o superior

Ejecutar:
  py main.py

Crear EXE:
  Doble clic en build_exe.bat
  El ejecutable quedara en dist\GlezRuda_Security.exe

FUNCIONES V1
- Escaneo de archivo, carpeta y escaneo rapido.
- Hash SHA-256 y base local de firmas.
- Incluye reconocimiento del archivo de prueba EICAR por hash (NO incluye malware ni el contenido EICAR).
- Cuarentena manual de detecciones.
- Restauracion desde cuarentena.
- Exclusiones de carpetas.
- Historial SQLite local.
- Archivo signatures.txt para agregar hashes SHA-256 conocidos.

SEGURIDAD
Esta V1 es un escaner complementario y no sustituye Microsoft Defender.
No desactiva Defender ni modifica configuraciones de seguridad de Windows.
La cuarentena solo se ejecuta tras confirmacion del usuario.

Agregar firmas:
Al primer inicio se crea:
%LOCALAPPDATA%\GlezRudaSecurity\signatures.txt
Formato por linea:
SHA256,nombre_de_amenaza
