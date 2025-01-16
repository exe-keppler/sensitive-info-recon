# Sensitive Info Recon

Este proyecto está diseñado para realizar análisis de información sensible en dominios usando APIs públicas como Web Archive, VirusTotal y AlienVault OTX. 

## Características

- Recupera URLs relacionadas con un dominio objetivo.
- Filtra archivos sensibles basados en extensiones comunes mediante expresiones regulares.
- Automatiza el reconocimiento y clasificación de recursos públicos.

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu-usuario/sensitive-info-recon.git
   cd sensitive-info-recon
   ```

2. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso

Ejecuta el script especificando el dominio y tu API key de VirusTotal:

```bash
python sensitive_info_analyzer.py -d example.com -k <tu_api_key>
```

### Parámetros

- `-d`, `--domain`: Dominio objetivo a analizar (e.g., `example.com`).
- `-k`, `--apikey`: API key válida de VirusTotal.

## Ejemplo

```bash
python sensitive_info_analyzer.py -d example.com -k XXXXX
```

## Salida esperada

El script mostrará las URLs relacionadas con archivos sensibles, como:

```
Found sensitive files:
https://example.com/config.json
https://example.com/backup.zip
https://example.com/database.sql
```

## Dependencias

- Python 3.8 o superior
- Módulos:
  - `requests`
  - `argparse`

## Advertencia

Este script debe usarse únicamente para fines educativos y de investigación con permiso explícito del dominio objetivo.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o pull request en este repositorio si tienes ideas o mejoras.
