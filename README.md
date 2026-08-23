# loglens

Analizador de logs local con reglas de detección — un **SIEM de bolsillo** para quien no tiene un SOC: detecta fuerza bruta SSH, enumeración de usuarios, escaneos web y picos de error directamente en tus ficheros de log. **Cero dependencias, 100% offline**: los logs nunca salen de tu máquina.

```
$ loglens /var/log/auth.log /var/log/nginx/access.log --report informe.html
✗ [high] Fuerza bruta SSH desde 198.51.100.23
         14 fallos en ≤600s · usuarios: root
✗ [high] Escaneo web desde 45.83.12.9
         30 respuestas 4xx en ≤300s (404×30) · /admin×5, /.env×5 …
! [warn] Sondeo de ruta sensible: /.env
         5 peticion(es) · origen: 45.83.12.9

65 eventos (35 auth, 30 web) · 8 hallazgo(s)
Informe HTML: informe.html
```

## Por qué

Los SIEM grandes (Wazuh, Elastic) son excelentes pero pesan toneladas y quieren tu telemetría. `loglens` hace una sola cosa: leer los logs que ya tienes en disco y responder *"¿alguien está intentando entrar?"* con reglas transparentes y ajustables. Es la herramienta que instalas en un VPS recién estrenado mientras decides si necesitas algo más serio.

## Reglas incluidas

| Regla | Qué detecta | Severidad |
|---|---|---|
| `brute_force` | ≥ N fallos de login desde una IP dentro de una ventana | high |
| `user_spray` | Una IP probando muchos usuarios distintos | warn |
| `web_scan` | Ráfaga de respuestas 4xx desde una IP | high |
| `error_spike` | Pico de errores 5xx del servidor | warn |
| `suspicious_path` | Sondeos a `/.env`, `/.git`, `/wp-login.php`, `/etc/passwd`, … | warn |

Todos los umbrales se ajustan por CLI (`--brute-threshold`, `--webscan-window`, …). El código de salida es `1` si hay hallazgos `high`: encadénalo en cron o systemd timers.

```bash
# chequeo diario a las 7:00
0 7 * * * /usr/local/bin/loglens /var/log/auth.log || wall "Revisa loglens!"
```

## Formatos soportados

- **auth.log / secure** (syslog): OpenSSH (`Failed password`, `Invalid user`, `Accepted password`)
- **access.log combinado** (nginx/Apache): IP, método, ruta, estado, User-Agent
- **Auto-detección** de tipo por línea; mezcla ambos ficheros en una sola invocación
- stdin: `journalctl -u sshd --since today | loglens`

## Informe HTML

Con `--report informe.html` genera un documento standalone (sin JS externo) con KPIs, hallazgos ordenados por severidad y una línea temporal de los primeros eventos. Ideal para adjuntar en un ticket o guardar como evidencia.

## Instalación

Python ≥ 3.9. Sin dependencias.

```bash
git clone https://github.com/ThorrijaDEV/loglens
cd loglens
python3 -m venv .venv && source .venv/bin/activate
pip install .
loglens --help
```

## Ética

`loglens` analiza **tus propios logs**, localmente. No escanea nada, no contacta con ningún servicio, no envía telemetría.

## Limitaciones v0.1

- Syslog sin año asume el actual (con corrección si la fecha queda en el futuro); usa `--year` para ficheros antiguos.
- Detección de escaneo de puertos real requiere logs de firewall (`nftables`/`iptables`) — roadmap.
- Sin estado entre ejecuciones: cada análisis es autónomo sobre los ficheros dados (roadmap: baseline incremental).

Roadmap: parseo de journalctl nativo, reglas YAML propias, export JSON, notificaciones (webhook), modo daemon con cola.

## Desarrollo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest   # 36 tests, todo offline con logs sintéticos
```

```
src/loglens/
├── parsers.py   # syslog + combined → Event (ts normalizado a epoch)
├── detect.py    # reglas con ventanas deslizantes → Finding
├── report.py    # plantilla HTML standalone
└── cli.py       # argparse + códigos de salida
tests/
```

## Licencia

[MIT](LICENSE)
