GLEZRUDA SECURITY V1.4
======================

NOVEDAD PRINCIPAL
- El motor de protección en tiempo real ahora es independiente de la interfaz.
- Al cerrar GlezRuda_Security.exe, GlezRuda_Security_Engine.exe continúa funcionando en segundo plano.
- El motor se registra para iniciar automáticamente al iniciar sesión en Windows cuando la protección está activada.
- El panel muestra: PROTECCIÓN EN SEGUNDO PLANO ACTIVA.
- Conserva escaneo manual, firmas SHA-256, cuarentena, exclusiones y licencia offline.

COMPILAR
1. Ejecute build_exe.bat.
2. La carpeta release contendrá:
   - GlezRuda_Security.exe
   - GlezRuda_Security_Engine.exe
3. Mantenga ambos EXE juntos en la misma carpeta.

FUNCIONAMIENTO
- Abra GlezRuda_Security.exe y active la licencia.
- Con Protección en tiempo real activada, el motor se inicia automáticamente.
- Puede cerrar la ventana principal. El motor continúa vigilando Downloads, Desktop y Documents.
- En el próximo inicio de sesión de Windows, el motor vuelve a iniciarse automáticamente.

NOTA
Esta aplicación es una protección complementaria basada en firmas SHA-256. Microsoft Defender permanece activo. No instala drivers kernel ni sustituye un antivirus comercial completo.
