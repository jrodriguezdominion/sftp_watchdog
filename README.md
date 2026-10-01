# Watchdog SFTP

Espejo en tiempo real de un árbol local hacia un servidor SFTP: copia inicial opcional y sincronización de cambios (crear, modificar, mover, borrar).

## Requisitos

- Python 3.10+ (3.8 puede funcionar con el venv del proyecto)
- Acceso SFTP/SSH al servidor destino

## Instalación

```bash
cd scripts/sftp_watchdog
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso interactivo

```bash
python sftp_watchdog.py
```

El script pide ruta local, ruta remota absoluta y credenciales.

## Carga inicial a escala (millones de archivos)

La copia inicial por SFTP es **secuencial** (un archivo por vez). Para árboles muy grandes conviene un flujo **híbrido**:

1. **Bulk con rsync** (reanudable, mucho más rápido):

   ```bash
   rsync -a --info=progress2 --partial --human-readable \
     /ruta/local/absoluta/ \
     usuario@host:/ruta/remota/absoluta/
   ```

   - La barra final en la ruta local copia el *contenido* dentro del destino remoto (alineado con la ruta remota que configuras en el watchdog).
   - Red lenta: puedes añadir `-z` (compresión).
   - No ejecutes rsync y la copia inicial del script **a la vez** sobre el mismo árbol.

2. **Espejo en tiempo real** sin repetir la carga:

   ```bash
   python sftp_watchdog.py --skip-initial-sync
   ```

### Opciones de línea de comandos

| Flag | Descripción |
|------|-------------|
| `--skip-initial-sync` | Omite la copia inicial; solo vigila cambios. |
| `--log-every N` | En copia inicial, log de progreso cada N archivos (default: 1000). Usa `--log-every 1` para log por archivo. |

Ejemplo tras rsync:

```bash
python sftp_watchdog.py --skip-initial-sync
```

## Permisos en el servidor

La ruta remota debe existir o tu usuario debe poder crear directorios bajo ella (home, upload, chroot). Si ves `Permission denied`, prueba la ruta con `sftp`/`mkdir` o pide al administrador la carpeta base con permisos de escritura.

## Pruebas

```bash
python -m unittest test_sftp_watchdog -v
```

## Servicio (ejemplo)

1. Ejecutar rsync una vez (o en cron hasta completar).
2. Mantener el watchdog en `tmux`/`systemd`:

   ```bash
   /ruta/a/.venv/bin/python /ruta/a/sftp_watchdog.py --skip-initial-sync
   ```

   Las credenciales siguen siendo interactivas; para automatización completa haría falta ampliar el script (variables de entorno o fichero de config), no incluido por defecto.
