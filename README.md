# warp-pool

Пул туннелей Cloudflare WARP для Xray / 3x-ui, который сам себя чинит.

Один WARP-outbound в 3x-ui — единая точка отказа: аккаунт протухает, эндпоинт деградирует,
и весь трафик выхода висит, пока кто-то не сменит ключи руками. warp-pool держит **N
независимых туннелей** (`wpool1..N`) со своими аккаунтами, постоянно проверяет каждый и
чинит лежащие. Xray балансирует между ними через `observatory` + `leastPing`.

```
клиент → xray (3x-ui) ─ balancer warp-bal ─┬─ freedom@wpool1 ─┐
                                            ├─ freedom@wpool2 ─┼─ Cloudflare WARP → интернет
                                            └─ freedom@wpoolN ─┘
                          warp-pool: держит wpoolN, пробует, чинит
```

## Возможности

- **Два движка** (`ENGINE`):
  - `wg` — ядерный WireGuard хоста. Трафик через контейнер не идёт, рестарт контейнера туннели
    не рвёт. Для зарубежных VPS.
  - `awg` — AmneziaWG в userspace внутри контейнера (`amneziawg-go`). Мусорные пакеты перед
    handshake, DPI не узнаёт WireGuard. Модуль ядра не нужен. Для хостов в РФ.
- **Автопочинка:** битый аккаунт → новая регистрация; мёртвый эндпоинт → другой, из другой /24.
- **Эндпоинты `auto`:** адреса подбираются из подсетей WARP, рабочие запоминаются, упавшие
  банятся на 6 ч, порт, на котором легли несколько IP, банится целиком.
- **Регистрация в обход блокировок:** напрямую → через HTTP-прокси → через уже живой туннель пула.
- **Fail-closed:** туннель без аккаунта — интерфейс-заглушка, xray не уйдёт мимо WARP с IP хоста.
- **Защита от петель:** лимит регистраций в час, паузы между действиями; если лежат *все*
  туннели — это сеть хоста, ротация не делается.
- TCP и UDP, IPv4 и IPv6 внутри туннелей.

## Как чинит

Туннель считается лежащим после 3 неудачных проб подряд (`cdn-cgi/trace` через интерфейс, ≈1,5 мин):

1. С этим ключом 5 минут не было ни одного handshake, или тот же эндпоинт работает у соседа —
   **аккаунт битый**, сразу регистрируется новый.
2. Иначе — **смена эндпоинта** (до 2 раз); старый уходит в бан.
3. Не помогло — **новый аккаунт** (не чаще раза в 10 мин на туннель, не больше 6 регистраций
   в час на хост).

## Требования

- Linux-хост с Docker и Docker Compose, KVM (не OpenVZ/LXC).
- `ENGINE=wg`: модуль `wireguard` в ядре хоста.
- `ENGINE=awg`: `/dev/net/tun`.
- Xray с поддержкой `sockopt.interface` (3x-ui подходит).

## Установка

### 1. Хост (один раз)

```bash
# только для ENGINE=wg
modprobe wireguard && echo wireguard > /etc/modules-load.d/wireguard.conf

# у всех туннелей один внутренний IP 172.16.0.2 — нужен loose rp_filter
cat > /etc/sysctl.d/90-warp-pool.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
sysctl --system
```

### 2. Запуск

```bash
git clone https://github.com/xatang/warp-pool.git && cd warp-pool
cp .env.example .env        # ENGINE, WARP_TUNNELS — остальное по умолчанию
docker compose up -d --build
docker logs -f warp-pool    # ждём account_created и [status] N/N живы
```

Проверка туннеля руками:

```bash
curl -s -m 5 --interface wpool1 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(warp|colo)='
```

### 3. 3x-ui

При старте контейнер печатает в лог готовые куски конфига (или `docker exec warp-pool python3
/app/warp_pool.py xray`):

1. **Outbounds:** «+ Исходящие» → JSON → вставить строку `wpoolN` → Создать. На каждый туннель.
   Это обычные `freedom` с `sockopt.interface` — ключей в них нет, ротация аккаунтов их не меняет.
2. **Balancers:** тег `warp-bal`, selector `wpool`, стратегия `leastPing`,
   fallback — старый `warp` или `direct`.
3. **Observatory** (Advanced): блок из лога, `probeInterval: 15s`.
4. **Routing:** `"outboundTag": "warp"` → `"balancerTag": "warp-bal"`.

Проверка: вкладка «Тест маршрута» должна показать `wpoolN`.

### Хост в РФ (ENGINE=awg)

На российских VPS обычно режется и WireGuard, и API регистрации `api.cloudflareclient.com`.

1. В `.env`: `ENGINE=awg`, `REG_DIRECT=0`.
2. Зарегистрировать один аккаунт там, где API доступен (например, на зарубежном хосте с пулом):
   ```bash
   docker exec warp-pool python3 -c "import sys;sys.path.insert(0,'/app');import warp_pool as w;a=w.register_account(['direct']);print(a['private_key'],a['v4'],a['v6'])"
   ```
3. Засеять им пул и запустить:
   ```bash
   docker compose run --rm warp-pool import 1 <PRIVATE_KEY> <V4> <V6>
   docker compose up -d --build
   ```
   Когда `wpool1` поднимется, остальные аккаунты зарегистрируются **через него**.

Не держи один ключ одновременно в пуле и в outbound 3x-ui — Cloudflare будет перекидывать
сессию между ними. Выходной IP WARP геолоцируется по стране клиента, а не по дата-центру
Cloudflare — с РФ-хоста геоIP будет RU.

## Эксплуатация

```bash
docker logs -f warp-pool                                    # [status] N/M живы + события
docker exec warp-pool python3 /app/warp_pool.py status      # JSON: задержка, colo, эндпоинт, баны
docker compose run --rm warp-pool down                      # снять интерфейсы и правила
```

События в логе: `account_created`, `endpoint_changed`, `endpoint_banned`, `account_rotated`,
`recovered`, `register_failed`, `rotation_blocked`, `all_down`.

`data/state.json` хранит приватные ключи аккаунтов — в бэкап можно, в git нельзя (уже в
`.gitignore`). Не копируй `data/` между хостами: у каждого хоста должны быть свои аккаунты.

## Настройки (`.env`)

| Переменная | По умолч. | |
|---|---|---|
| `ENGINE` | `wg` | `wg` — ядерный WireGuard, `awg` — AmneziaWG |
| `WARP_TUNNELS` | 3 | сколько туннелей |
| `ENDPOINTS` | `auto` | `auto` или список `ip:port,ip:port,...` |
| `AUTO_SUBNETS` / `AUTO_PORTS` | подсети WARP / 14 портов | откуда брать адреса в `auto` |
| `BAD_ENDPOINT_TTL` | 21600 | сек бана упавшего эндпоинта |
| `BAD_PORT_AFTER` | 3 | столько IP легли на одном порту → порт в бан |
| `AWG_JC` / `AWG_JMIN` / `AWG_JMAX` | 4 / 40 / 70 | мусорные пакеты AmneziaWG |
| `REG_DIRECT` | 1 | регистрировать аккаунты напрямую |
| `REG_PROXY` | — | HTTP-прокси для регистрации |
| `REG_VIA_TUNNEL` | 1 | регистрировать через живой туннель пула |
| `PROBE_INTERVAL` / `PROBE_TIMEOUT` | 30 / 8 | сек между пробами / таймаут пробы |
| `FAIL_THRESHOLD` | 3 | неудач подряд до действий |
| `DEAD_ACCOUNT_AFTER` | 300 | сек без handshake → аккаунт битый |
| `ENDPOINT_TRIES` | 2 | смен эндпоинта до новой регистрации |
| `ACTION_COOLDOWN` | 120 | сек между действиями по одному туннелю |
| `REG_COOLDOWN` | 600 | сек между регистрациями одного туннеля |
| `MAX_REG_PER_HOUR` | 6 | лимит регистраций на хост |
| `SUMMARY_INTERVAL` | 600 | строка `[status]` раз в N сек |
| `MTU` | 1280 | MTU туннелей |
| `ENABLE_IPV6` | 1 | IPv6 внутри туннелей (сам выключится, если на хосте нет v6) |
| `TABLE_BASE` / `RULE_PRIO_BASE` | 5100 | номера таблиц маршрутизации и `ip rule` |

Команды: `run` (по умолчанию), `status`, `xray`, `down`, `import N PRIVKEY V4 [V6]`.

## Известные особенности

- Сервисы, которые привязывают токен к IP (Twitch usher, ссылки googlevideo), могут ломаться,
  если балансер отправил связанные запросы через разные туннели, а часть выходных IP WARP
  такими CDN блокируется. Такие домены лучше пустить мимо пула отдельным правилом routing.
- Аккаунты, зарегистрированные пачкой, иногда приходят мёртвыми — демон это распознаёт и
  перерегистрирует.
- `ENGINE=awg`: рестарт контейнера коротко рвёт туннели (userspace-процессы).

## Отказ от ответственности

Неофициальный проект, с Cloudflare не связан. Использование WARP таким способом может
противоречить условиям Cloudflare — на свой риск.
