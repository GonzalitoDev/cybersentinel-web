# CyberSentinel Web

Analizador de archivos que corre entero en el navegador. Revisa carpetas o archivos sueltos y ningún archivo sale del dispositivo.

## Qué revisa

- Tipo real de cada archivo según sus primeros bytes, sin fiarse de la extensión.
- SHA-256 de cada archivo, comparado con una base local de firmas. Un archivo sale como **CRÍTICO** sólo si coincide exactamente con una firma.
- Extensiones engañosas (`factura.pdf.apk`, un `.jpg` que en realidad es un APK) y nombres con caracteres invertidos o invisibles.
- Archivos y carpetas ocultos, duplicados sospechosos y ejecutables guardados en carpetas de fotos o música.
- PDF con JavaScript o `/Launch` y documentos de Office con macros.
- APK sin instalarlos: lee el manifiesto y revisa permisos, servicios de accesibilidad e imitaciones de apps conocidas.
- Historial, cuarentena y registro de acciones. El informe se puede exportar en PDF o JSON.

## Límites

- Una página web no puede ver las apps instaladas ni la configuración del teléfono. Para eso está la versión Android.
- La cuarentena real (sacar el archivo de su carpeta) sólo funciona en navegadores que dejan abrir carpetas con permiso de escritura, como Chrome o Edge de computadora.
- Los datos (historial, firmas, cuarentena) se guardan en el navegador. Si borrás los datos del sitio, se pierden.

## Firmas

De fábrica sólo trae la firma de prueba EICAR. Para detectar malware conocido, importá desde **Configuración** una lista de hashes SHA-256 en `.txt`, `.csv` o `.zip`, por ejemplo la exportación de MalwareBazaar.

## Publicación

Es un sitio estático: `index.html` más `vercel.json` con encabezados de seguridad. No necesita compilación.
