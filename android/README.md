# CyberSentinel Mobile

Antivirus Android nativo, ligero y privado. Kotlin + Jetpack Compose, análisis 100 % local (la app **no declara el permiso de Internet**).

## Cómo compilar

1. Abrí la carpeta en **Android Studio** (Ladybug 2024.2 o más nuevo, JDK 17).
2. Dejá que sincronice Gradle (AGP 8.7.3, Kotlin 2.0.21, Gradle 8.10.2 vía wrapper).
3. Ejecutá en un teléfono o emulador con Android 8.0 (API 26) o superior.

Pruebas de las reglas de detección (JVM, sin emulador):

```
./gradlew test
```

## Qué hace (todo implementado)

| Función | Cómo lo hace |
|---|---|
| Escaneo de archivos | Recorre las carpetas autorizadas (SAF) o todo el almacenamiento compartido si activás "Acceso a todos los archivos". Omite `Android/data` y `Android/obb`. |
| SHA-256 + firmas | Calcula el hash de cada archivo (límite configurable) y lo busca en la base SQLite de firmas. **CRÍTICO sólo si hay coincidencia exacta.** |
| Tipo real | Lee los *magic bytes* (APK, DEX, ELF, EXE, PDF, Office, ZIP, imágenes, audio, video…) y abre los ZIP para distinguir APK/JAR/Office. |
| Extensiones engañosas | `.jpg` que en realidad es APK, doble extensión (`factura.pdf.apk`), espacios antes de la extensión, carácter RLO. |
| Archivos ocultos | Archivos y carpetas que empiezan con punto, con fecha de creación (si el sistema la guarda), modificación, tamaño y ubicación. |
| Duplicados sospechosos | Mismo SHA-256 con distinto nombre/extensión, o ejecutables duplicados. |
| Ubicaciones inusuales | Ejecutables dentro de DCIM, Pictures, Music, etc., o en carpetas ocultas. |
| Contenido | PDF con `/JavaScript` o `/Launch`, Office con macros (VBA), comprimidos con ejecutables adentro. |
| APK sueltos | Lee el manifiesto con `PackageManager.getPackageArchiveInfo` (sin instalar) y evalúa permisos, accesibilidad, administración e imitación. |
| Apps instaladas | Origen real (`getInstallSourceInfo`): tienda, APK manual, otra app o desconocido. Permisos concedidos, accesibilidad activa, administrador activo, lector de notificaciones, app de SMS predeterminada, ícono oculto, imitación de marcas (homoglifos incluidos), permisos innecesarios para el tipo de app. Hash del APK contra la base de firmas. |
| Dispositivo | Bloqueo de pantalla, depuración USB, opciones de desarrollador, antigüedad del parche de seguridad. |
| Cuarentena | Copia ofuscada en el almacenamiento privado, verificación SHA-256, recién después borra el original. Restaurar (al lugar original o donde elijas) o eliminar, siempre con confirmación. Nunca toca rutas del sistema. |
| Registro | Cada análisis, cuarentena, restauración, eliminación, importación y exportación queda en SQLite con fecha y hora. |
| Informes | Pantalla de informe y exportación a **PDF** (`PdfDocument`, sin librerías) por el selector del sistema. |

Niveles: **CRÍTICO** (firma confirmada) · **ALTO** · **MEDIO** · **BAJO** · **SEGURO**. Un nombre raro por sí solo nunca pasa de BAJO. El "nivel general" sale del hallazgo pendiente más grave: no hay porcentajes inventados.

## Base de firmas

La app trae sólo la firma de prueba **EICAR** (inofensiva). Para detectar malware real:

1. Desde el navegador del teléfono, descargá una lista de SHA-256 (por ejemplo, la exportación de MalwareBazaar de abuse.ch en `.txt`, `.csv` o `.zip`).
2. En **Ajustes → Base de firmas → Importar archivo**, elegila. Se importa localmente.

Para probar la detección: creá un archivo de texto con la cadena EICAR estándar, guardalo en una carpeta autorizada y hacé un análisis. Debe salir como CRÍTICO.

## Permisos

| Permiso | Para qué |
|---|---|
| `QUERY_ALL_PACKAGES` | Ver todas las apps instaladas (uso permitido para antivirus en Google Play, requiere declaración). |
| `MANAGE_EXTERNAL_STORAGE` (opcional, Android 11+) | Análisis completo, incluida Descargas (Android no permite autorizar Descargas por SAF). |
| `READ/WRITE_EXTERNAL_STORAGE` (sólo Android 8–10) | Equivalente en versiones viejas. |
| `REQUEST_DELETE_PACKAGES` | Abrir el diálogo oficial de desinstalación. |
| — sin `INTERNET` — | Imposible enviar datos fuera del teléfono. |

## Estructura

```
app/src/main/java/com/cybersentinel/mobile/
├── data/        Models.kt, Database.kt (SQLite: scans, findings, signatures, quarantine, action_log, trusted)
├── scanner/     ScanEngine (orquestación), ScanNode (archivo/SAF), FileTypes, FileAnalysis (lectura en una pasada + reglas),
│                AppScanner + AppRules + AppKnowledge (permisos, tiendas, marcas), DeviceAuditor, SignatureImporter, StorageAccess
├── quarantine/  QuarantineManager
├── report/      Recommendations, PdfReport
└── ui/          Compose: Inicio, Análisis, Archivos, Apps, Detalle, Historial, Informe, Cuarentena, Registro, Ajustes
```

## Limitaciones honestas

- No es protección en tiempo real: analiza cuando vos lo pedís.
- Android no permite leer datos privados de otras apps ni carpetas del sistema; la app no lo intenta.
- La detección de amenazas **confirmadas** depende de la base de firmas que importes. Las reglas heurísticas marcan elementos sospechosos, no "virus".
- El análisis corre mientras la app esté en memoria; si Android cierra el proceso, ese análisis queda incompleto.
- Muchas particiones de Android no guardan la fecha de creación: en ese caso se muestra "no disponible".
