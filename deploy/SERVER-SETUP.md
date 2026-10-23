# Запуск сервера Hookah Party: пошагово

Инструкция для владельца, без опыта администрирования. Команды копируйте целиком. Где написано `ВАШ-…` — подставьте своё.
Займёт 1–2 часа. Делать по порядку: каждый следующий шаг опирается на предыдущий.

Что понадобится:

- домен (например, `hookahparty.kg`), купленный у любого регистратора;
- сервер (VPS) — шаг 1;
- Mac с терминалом;
- менеджер паролей (iCloud «Пароли», 1Password, Bitwarden) — туда пойдут ключи;
- на телефоне приложение для одноразовых кодов (Google Authenticator или «Пароли» на iPhone);
- договор с SMS-шлюзом (например, Nikita — smspro.nikita.kg): логин, пароль, имя отправителя.

> **Три ключа в `.env` — это и есть доступ к данным.** `DATA_KEY` шифрует номера телефонов, `BACKUP_KEY` — резервные копии,
> `ADMIN_CODE_KEY` — код панели администратора. Потеряете `DATA_KEY` или `BACKUP_KEY` — данные и копии не расшифровать.
> Поэтому копия `.env` должна лежать в менеджере паролей, а не только на сервере. Ключи никому не пересылайте.

---

## 1. Сервер и домен

**Сервер.** Любой VPS: Ubuntu **24.04 LTS**, 1 процессор, 1–2 ГБ памяти, от 20 ГБ диска, IPv4 (IPv6 — если дают).
Ближе к пользователям — быстрее (Европа или местный хостинг в Кыргызстане). При создании:

- система — Ubuntu 24.04;
- способ входа — **SSH-ключ** (шаг 2), не пароль;
- запишите IP-адрес сервера.

**Домен.** В панели регистратора создайте запись **A**: имя `@` (сам домен) → IP сервера. Если у сервера есть IPv6 — ещё
запись **AAAA** с IPv6-адресом. Запись расходится по интернету от минут до нескольких часов — пока делайте следующие шаги.

## 2. Ключ для входа на сервер (на Mac)

Отдельный ключ только для этого сервера:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/hookah_server -C "hookah-server"
```

Придумайте фразу-пароль к ключу и сохраните её в менеджере паролей. Открытая часть ключа:

```bash
cat ~/.ssh/hookah_server.pub
```

Эту строку (начинается с `ssh-ed25519`) вставьте в панели хостинга при создании сервера («SSH keys»).

Чтобы входить коротко `ssh hookah`, добавьте в `~/.ssh/config` (имя `marlen` дальше везде — ваше будущее имя на сервере,
латиницей; можно любое):

```
Host hookah
  HostName ВАШ-IP-СЕРВЕРА
  User marlen
  IdentityFile ~/.ssh/hookah_server
```

## 3. Первый вход: обновления, часовой пояс, свой пользователь

Первый раз входим как root:

```bash
ssh -i ~/.ssh/hookah_server root@ВАШ-IP-СЕРВЕРА
```

На сервере:

```bash
apt update && apt full-upgrade -y
timedatectl set-timezone Asia/Bishkek
adduser marlen                 # придумайте длинный пароль (он нужен для sudo) и сохраните в менеджере паролей
usermod -aG sudo,adm marlen      # sudo — права администратора, adm — чтение системных журналов
install -d -m 700 -o marlen -g marlen /home/marlen/.ssh
install -m 600 -o marlen -g marlen /root/.ssh/authorized_keys /home/marlen/.ssh/authorized_keys
reboot
```

Если хостинг сам создал пользователя (например, `ubuntu`) и пускает под ним — можно работать под ним, только в
`~/.ssh/config` и дальше в командах используйте это имя.

Через минуту, **с Mac**, входим уже под своим именем и проверяем sudo:

```bash
ssh hookah
sudo -v            # спросит пароль пользователя marlen — значит, sudo работает
```

Дальше все команды — в этой сессии, под своим пользователем.

## 4. Код сайта на сервере

```bash
sudo git clone https://github.com/marlendiusheew-sudo/hookah-party.git /opt/hookah-party
sudo chown -R $USER:$USER /opt/hookah-party
cd /opt/hookah-party
```

Код принадлежит вам, сам сервис будет работать от отдельного пользователя `hookah` и менять код не сможет.

## 5. Защита SSH: только ключ, без root и без паролей

> **Внимание:** ошибка на этом шаге закрывает вход на сервер. Не закрывайте текущую сессию, пока не проверите вход в новом окне.

```bash
sed "s/CHANGE_ME_USERNAME/$USER/" deploy/sshd_config.d/10-hookah-hardening.conf | sudo tee /etc/ssh/sshd_config.d/10-hookah-hardening.conf
sudo sshd -t && sudo systemctl restart ssh
```

`sshd -t` ничего не написал — ошибок нет. Теперь **в новом окне терминала на Mac**: `ssh hookah`. Вошли — хорошо, новое окно
можно закрыть. Не пускает — в старой сессии откатите и разберитесь:

```bash
sudo rm /etc/ssh/sshd_config.d/10-hookah-hardening.conf && sudo systemctl restart ssh
```

## 6. Межсетевой экран

Открыты останутся только SSH, 80 и 443. Порт Node (3000) снаружи будет закрыт.

```bash
sudo bash deploy/firewall.sh
```

В конце скрипт покажет правила: `OpenSSH LIMIT`, `80/tcp ALLOW`, `443/tcp ALLOW`.

## 7. Автоматические обновления безопасности

```bash
sudo apt install -y unattended-upgrades
sudo cp deploy/apt.conf.d/52hookah-unattended-upgrades /etc/apt/apt.conf.d/
sudo unattended-upgrade --dry-run 2>&1 | tail -3
```

Ubuntu будет сама ставить исправления безопасности, а если нужна перезагрузка — перезагрузится в 04:30. Сайт поднимется сам.

## 8. Node.js 24

В Ubuntu старый Node, ставим 24-ю версию из репозитория NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x -o /tmp/nodesource_setup.sh
sudo bash /tmp/nodesource_setup.sh
sudo apt install -y nodejs
node --version          # v24.7 или новее
```

`npm install` на сервере не нужен: у сервера нет сторонних зависимостей.

## 9. Пользователь сервиса, папка данных и файл `.env`

```bash
sudo adduser --system --group --home /var/lib/hookah --shell /usr/sbin/nologin hookah
sudo install -d -m 750 -o hookah -g hookah /var/lib/hookah
sudo install -d -m 700 -o hookah -g hookah /opt/hookah-party/server/data
sudo install -m 600 -o hookah -g hookah /dev/null /opt/hookah-party/.env
```

Заполняем `.env`. Ключ `DATA_KEY` создаётся прямо в команде и на экран не выводится. Перед запуском замените номер
владельца (`ADMIN_PHONES`, в международном формате) и данные SMS-шлюза:

```bash
sudo -u hookah tee -a /opt/hookah-party/.env > /dev/null <<EOF
NODE_ENV=production
PORT=3000
TRUST_PROXY=1
SEED=0
DB_PATH=/opt/hookah-party/server/data/hookah.db
DATA_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
ADMIN_PHONES=+996ВАШ-НОМЕР
SMS_PROVIDER=nikita
NIKITA_LOGIN=ВАШ-ЛОГИН
NIKITA_PASSWORD=ВАШ-ПАРОЛЬ
NIKITA_SENDER=ВАШ-ОТПРАВИТЕЛЬ
BACKUP_KEEP=14
EOF
```

- `SEED=0` обязательно: иначе в пустой базе появятся демо-пользователи с паролем `hookah`.
- `TRUST_PROXY=1` — сервер стоит за nginx и берёт адрес посетителя из заголовка, который ставит nginx.
- Неудобно править в терминале — вставьте блок как есть, а значения `ВАШ-…` поправьте потом:
  `sudo nano /opt/hookah-party/.env` (сохранить — Ctrl+O, Enter; выйти — Ctrl+X).

**Ключ панели администратора** — тот же, что у вас на Mac (им зашифрован код панели в репозитории). Перенесём его, не
показывая на экране. **На Mac**, в новом окне:

```bash
grep '^ADMIN_CODE_KEY=' ~/hookah-party/.env | ssh hookah 'umask 077; cat > ~/admin-code-key.txt'
```

**На сервере:**

```bash
cat ~/admin-code-key.txt | sudo -u hookah tee -a /opt/hookah-party/.env > /dev/null && shred -u ~/admin-code-key.txt
```

**Ключ резервных копий** — создаёт сама программа и сразу вписывает в `.env`:

```bash
cd /opt/hookah-party
sudo -u hookah node server/backup.js key
```

Проверка — имена есть, значения скрыты, права `-rw------- hookah hookah`:

```bash
sudo -u hookah sed -E 's/=.+/=•••/' /opt/hookah-party/.env
sudo ls -l /opt/hookah-party/.env
```

**Сохраните `.env` в менеджере паролей.** Покажите файл и скопируйте всё содержимое в новую запись
(«Hookah Party — .env сервера»), затем очистите экран:

```bash
sudo cat /opt/hookah-party/.env
clear
```

## 10. Запуск сайта как службы

```bash
cd /opt/hookah-party
sudo cp deploy/hookah-party.service deploy/hookah-backup.service deploy/hookah-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hookah-party
systemctl status hookah-party --no-pager
curl -s http://127.0.0.1:3000/api/health
```

Должно быть `active (running)` и `{"ok":true,"mode":"server",...}`. Журнал сервера: `journalctl -u hookah-party -n 30 --no-pager`.

Если служба не стартует:

- `status=226/NAMESPACE` — нет папки `/opt/hookah-party/server/data` (шаг 9);
- «В production нужен DATA_KEY» — в `.env` нет `DATA_KEY`;
- в журнале «Operation not permitted» — в `/etc/systemd/system/hookah-party.service` закомментируйте строки
  `SystemCallFilter` и `SystemCallErrorNumber`, затем `sudo systemctl daemon-reload && sudo systemctl restart hookah-party`
  и сообщите разработчику;
- в статусе «start request repeated too quickly» — сервис падал при каждом запуске, и после 10 попыток за 2 минуты systemd
  перестал его поднимать. Причина — в журнале (`journalctl -u hookah-party -n 50 --no-pager`); после исправления:
  `sudo systemctl reset-failed hookah-party && sudo systemctl start hookah-party`.

Насколько процесс изолирован (чем меньше число, тем лучше): `systemd-analyze security hookah-party --no-pager | tail -1`.

**Пределы ресурсов.** Службе разрешено до 512 МБ памяти (с 384 МБ ядро её притормаживает), 64 потока и 4096 открытых
файлов: даже при наплыве запросов она не отнимет память у nginx, SSH и резервных копий. Упрётся в 512 МБ — процесс
завершится, и systemd через 3 секунды запустит его заново. Сколько занято сейчас — строка `Memory:` в
`systemctl status hookah-party`. Если в журнале «killed by the OOM killer» при обычной работе, без наплыва запросов, а памяти
у сервера 2 ГБ или больше, — поднимите `MemoryHigh` и `MemoryMax` в `/etc/systemd/system/hookah-party.service` (например,
до `768M` и `1G`), затем `sudo systemctl daemon-reload && sudo systemctl restart hookah-party`.

## 11. Домен, nginx и HTTPS

Проверьте, что домен уже указывает на сервер (должен вывести IP сервера):

```bash
getent hosts ВАШ-ДОМЕН
```

Ставим nginx и certbot, временно включаем простую настройку для получения сертификата:

```bash
cd /opt/hookah-party
DOMAIN=ВАШ-ДОМЕН
sudo apt install -y nginx certbot
sudo mkdir -p /var/www/letsencrypt
sudo rm -f /etc/nginx/sites-enabled/default
sudo sed "s/hookahparty.example/$DOMAIN/g" deploy/nginx-bootstrap.conf | sudo tee /etc/nginx/sites-available/hookah-party > /dev/null
sudo ln -sf /etc/nginx/sites-available/hookah-party /etc/nginx/sites-enabled/hookah-party
sudo nginx -t && sudo systemctl reload nginx
```

Получаем сертификат (адрес почты — для учётной записи Let's Encrypt):

```bash
sudo certbot certonly --webroot -w /var/www/letsencrypt -d $DOMAIN -m ВАШ-EMAIL --agree-tos --no-eff-email --deploy-hook "systemctl reload nginx"
```

Ставим основную настройку (HTTPS, лимиты, заголовки) и проверяем автопродление:

```bash
sudo sed "s/hookahparty.example/$DOMAIN/g" deploy/nginx.conf | sudo tee /etc/nginx/sites-available/hookah-party > /dev/null
sudo nginx -t && sudo systemctl reload nginx
sudo certbot renew --dry-run
```

Откройте `https://ВАШ-ДОМЕН` — должен открыться сайт с замком в адресной строке. Сертификат продлевается сам (таймер certbot),
после продления nginx перезагружается сам.

Лимиты nginx (и сам сервер в своих) считают одним посетителем IPv4-адрес, а для IPv6 — всю сеть /64 (её провайдер
выдаёт одному устройству или дому). От одного посетителя — не больше 50 одновременных запросов (общего потолка на весь сайт нет: несколько адресов
с медленными запросами заняли бы его и закрыли сайт для всех); сверх лимита nginx отвечает «429 Too Many Requests».

> Поддомен `www` в этой настройке не обслуживается. Нужен — добавьте запись в DNS, `-d www.$DOMAIN` в certbot и
> `www.ВАШ-ДОМЕН` в `server_name`.

## 12. Резервные копии

Каждую ночь в 05:30 база копируется, проверяется и шифруется ключом `BACKUP_KEY`; хранятся последние 14 копий.

```bash
sudo systemctl enable --now hookah-backup.timer
sudo systemctl start hookah-backup
journalctl -u hookah-backup -n 5 --no-pager
sudo ls -l /opt/hookah-party/server/data/backups
```

Должна появиться строка «Копия готова: …db.enc (зашифрована …)».

**Учебное восстановление** — убедиться, что копия действительно открывается (рабочую базу не трогает):

```bash
cd /opt/hookah-party
LAST=$(sudo ls /opt/hookah-party/server/data/backups | grep '\.db\.enc$' | tail -1)
sudo -u hookah node server/backup.js restore server/data/backups/$LAST /var/lib/hookah/restore-test.db
sudo rm /var/lib/hookah/restore-test.db
```

Команда покажет число строк в каждой таблице. Повторяйте раз в месяц.

## 13. fail2ban: бан тех, кто подбирает пароли

```bash
cd /opt/hookah-party
sudo apt install -y fail2ban
sudo cp deploy/fail2ban/filter.d/hookah-party.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/hookah-party.local /etc/fail2ban/jail.d/
sudo systemctl restart fail2ban
sudo fail2ban-client status
```

В списке должны быть `hookah-party` и `sshd`. Правила: 10 неверных паролей или кодов из SMS (вход, регистрация, панель
администратора, удаление аккаунта, смена пароля) за час с одного IP — бан этого IP на сайте на час, повторно — дольше
(до недели). SSH с этого IP остаётся доступен. Подробности и почему так — в комментариях файлов в `deploy/fail2ban/`.

**IPv6: fail2ban банит один адрес, а не сеть.** У IPv6 одному устройству принадлежит целая сеть /64 — миллиарды адресов,
и упорный подборщик может брать новый адрес на каждую попытку: ни один адрес не наберёт 10 штрафных очков. Частоту ему
всё равно ограничат nginx и сам сервер — они считают всю сеть /64 одним посетителем. Если в `sudo fail2ban-client status hookah-party`
много адресов с одинаковыми первыми четырьмя группами (`2001:db8:1234:5678:…`), закройте сайт для всей сети /64 вручную —
вместо `IPV6-АДРЕС` подставьте любой из этих адресов:

```bash
NET=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1] + "/64", strict=False))' IPV6-АДРЕС)
echo $NET                      # например, 2001:db8:1234:5678::/64
sudo ufw prepend deny from $NET to any app "Nginx Full" comment "hookah: ban /64"
```

Именно `prepend`: правило должно стоять раньше разрешений для 80 и 443, иначе не сработает. Такой бан бессрочный, пока
его не снимут (раздел 19); SSH из этой сети, как и при бане fail2ban, остаётся доступен.

Кто сейчас в бане и как снять бан (например, пожаловался человек за общим IP мобильного оператора):

```bash
sudo fail2ban-client status hookah-party
sudo fail2ban-client set hookah-party unbanip IP-АДРЕС
```

Если fail2ban не запускается с ошибкой про `asynchat` — обновите пакет: `sudo apt update && sudo apt install --only-upgrade fail2ban`.

## 14. Срок хранения журналов — 90 дней

В политике конфиденциальности обещано хранить журнал безопасности не дольше 90 дней. Журнал в базе сервер чистит сам,
системный журнал (в нём тоже есть IP) ограничиваем так:

```bash
cd /opt/hookah-party
sudo mkdir -p /etc/systemd/journald.conf.d
sudo cp deploy/journald.conf.d/hookah-retention.conf /etc/systemd/journald.conf.d/
sudo systemctl restart systemd-journald
journalctl --disk-usage
```

Журналы nginx Ubuntu хранит 14 дней — это укладывается в обещание.

## 15. Копии вне сервера (по желанию, но очень советую)

Если сервер пропадёт целиком, копии на нём пропадут вместе с ним. Уносим зашифрованные копии в облачное хранилище
(S3-совместимое: Cloudflare R2, Backblaze B2, Yandex Object Storage и т. п.). Файлы зашифрованы `BACKUP_KEY`, хранилище их
содержимого не видит.

1. В панели хранилища создайте бакет `hookah-backups` и ключ доступа **только к этому бакету**.
2. На сервере:

```bash
cd /opt/hookah-party
sudo apt install -y rclone
sudo -u hookah -H rclone config          # n → имя: offsite → тип: s3 → провайдер и ключи из панели хранилища
sudo -u hookah -H rclone lsd offsite:     # должен показать бакет hookah-backups
sudo cp deploy/hookah-offsite.service deploy/hookah-offsite.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hookah-offsite.timer
sudo systemctl start hookah-offsite && journalctl -u hookah-offsite -n 10 --no-pager
sudo -u hookah -H rclone ls offsite:hookah-backups
```

Каждое утро в 06:15 новые копии уезжают в хранилище, копии старше 14 дней там удаляются (тот же срок, что на сервере и в политике конфиденциальности).
Ещё надёжнее — если хранилище само умеет хранить версии или удалять файлы по сроку: тогда ключу rclone можно не давать права
удалять, и взломщик сервера не сотрёт копии.

## 16. Первый вход владельца и права администратора

1. Откройте `https://ВАШ-ДОМЕН`, зарегистрируйтесь своим номером (тем, что в `ADMIN_PHONES`) — придёт SMS с кодом.
2. Выдайте себе права:

```bash
cd /opt/hookah-party
sudo -u hookah node server/admin.js grant +996ВАШ-НОМЕР
sudo -u hookah node server/admin.js list
```

3. Сразу же войдите на сайт заново: «Профиль» → «Администрирование». Введите пароль — откроется экран подключения
   приложения для кодов. Отсканируйте QR-код приложением на телефоне и введите шестизначный код из него.
   Не откладывайте: пока приложение не подключено, панель открывается одним паролем (только этот экран), и подключит
   приложение тот, кто сделает это первым.
   Резервных кодов нет. Сохраните ключ для ручного ввода (он под QR-кодом) в менеджере паролей или включите облачную
   копию в приложении; иначе после потери телефона доступ вернёт только `totp-reset` (раздел 19).

## 17. Итоговая проверка

На сервере:

```bash
DOMAIN=ВАШ-ДОМЕН
curl -sI https://$DOMAIN | grep -iE "^(strict-transport-security|content-security-policy|x-frame-options|server):"
curl -s https://$DOMAIN/api/health
curl -sI http://$DOMAIN | head -2                     # 301 → https
sudo ufw status verbose
sudo fail2ban-client status
systemctl list-timers --no-pager | grep -E "hookah|certbot"
```

Ожидаемо: `Strict-Transport-Security` и `Content-Security-Policy` есть, `server: nginx` без номера версии,
`/api/health` отвечает `"mode":"server"`, в таймерах — `hookah-backup` и `certbot`.

С Mac — порт Node снаружи закрыт (команда должна завершиться ошибкой или таймаутом):

```bash
curl --max-time 5 http://ВАШ-IP-СЕРВЕРА:3000/api/health
```

В браузере:

- https://www.ssllabs.com/ssltest/ — введите домен; ожидается оценка **A** или **A+**;
- https://securityheaders.com/ — введите `https://ВАШ-ДОМЕН`; ожидается **A** или выше.

## 18. Обновление сайта

```bash
cd /opt/hookah-party
git pull
sudo systemctl restart hookah-party
journalctl -u hookah-party -n 20 --no-pager
```

Если в обновлении менялись файлы в `deploy/` — скопируйте изменённые туда же, куда на шагах выше (и `sudo systemctl daemon-reload`
для файлов `.service`/`.timer`, `sudo nginx -t && sudo systemctl reload nginx` для nginx).

Раз в месяц: `sudo apt update && sudo apt upgrade -y && sudo systemctl restart hookah-party` — это обновит и Node.js.

## 19. Если что-то случилось

### Ключ `DATA_KEY` или весь `.env` мог утечь

Сменить ключ данных (номера перешифруются, перед этим сделается зашифрованная копия; вход у пользователей сохранится):

```bash
sudo systemctl stop hookah-party
cd /opt/hookah-party
sudo -u hookah node server/rotate-key.js
sudo systemctl start hookah-party
```

Команда сама заменит строку `DATA_KEY` в `.env` и ничего секретного не покажет. Прежний ключ она сохранит в
`server/data/old-data-key-….env` — он нужен, только чтобы открыть копии, сделанные до смены; когда они устареют
(через 14 дней), удалите файл: `sudo sh -c 'shred -u /opt/hookah-party/server/data/old-data-key-*.env'`.
Сохраните новый `.env` в менеджере паролей.

Если утёк весь `.env`, дополнительно:

- **SMS-шлюз** — смените пароль в его панели и в `.env` (`NIKITA_PASSWORD`), затем `sudo systemctl restart hookah-party`;
- **BACKUP_KEY** — для новых копий нужен новый ключ. Старые копии откроет только старый ключ — он остаётся в прежней
  записи в менеджере паролей.

  ```bash
  sudo sed -i '/^BACKUP_KEY=/d' /opt/hookah-party/.env
  cd /opt/hookah-party && sudo -u hookah node server/backup.js key
  ```

- **ADMIN_CODE_KEY** — на Mac, в папке проекта: `node server/admin.js rekey` (панель перешифруется, ключ в локальном `.env`
  заменится), затем выложите обновлённый `server/private/admin-panel.enc` (коммит и push). На сервере: `git pull`,
  удалите старую строку (`sudo sed -i '/^ADMIN_CODE_KEY=/d' /opt/hookah-party/.env`), перенесите новую тем же способом,
  что в шаге 9, и `sudo systemctl restart hookah-party`;
- **выход всех пользователей** — ниже.

После всех замен сохраните новый `.env` в менеджере паролей (`sudo cat /opt/hookah-party/.env`, затем `clear`).

### Выйти из всех сессий на всех устройствах

Свои сессии пользователь завершает сам: «Профиль» → «Настройки» → «Безопасность» → «Выйти на всех устройствах». Если пароль
могли узнать — там же «Сменить пароль»: остальные сессии завершатся сразу. Забыл пароль — «Забыли пароль?» на странице входа:
вход по коду из SMS, и 15 минут новый пароль задаётся без старого. Завершить сессии всех
пользователей сразу (каждому придётся войти заново):

```bash
sudo -u hookah node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.argv[1]);db.exec('PRAGMA busy_timeout=5000');console.log('Сессий завершено:',db.prepare('DELETE FROM sessions').run().changes)" /opt/hookah-party/server/data/hookah.db
```

Забрать права администратора у пользователя (его сессии тоже завершатся):
`sudo -u hookah node server/admin.js revoke +996НОМЕР`.

### Человек просит удалить аккаунт, а войти не может

Обычно человек удаляет аккаунт сам (Профиль → Настройки → «Удаление аккаунта»), а забытый пароль заменяет через «Забыли пароль?».
Если нет ни пароля, ни доступа к номеру, удалите аккаунт из консоли — сначала убедитесь, что просит владелец номера:

```bash
cd /opt/hookah-party
sudo -u hookah node server/admin.js delete +996НОМЕР        # только сводка: что удалится (ничего не трогает)
sudo -u hookah node server/admin.js delete +996НОМЕР --yes  # удалить
```

Удаляется всё то же, что при удалении из настроек: гости его предстоящих сборов получат уведомление об отмене, журнал
безопасности обезличится, а само удаление попадёт в журнал с последними цифрами номера. Сервер останавливать не нужно.

### Потерян телефон с приложением для кодов

Сбросить одноразовые коды владельцу (после этого настройте их заново, шаг 16):

```bash
cd /opt/hookah-party
sudo -u hookah node server/admin.js totp-reset +996ВАШ-НОМЕР
```

### Вернуть базу из резервной копии

```bash
sudo systemctl stop hookah-party
cd /opt/hookah-party
sudo ls /opt/hookah-party/server/data/backups                       # выберите копию по дате
sudo -u hookah node server/backup.js restore server/data/backups/hookah-ДАТА.db.enc server/data/restored.db
D=/opt/hookah-party/server/data
for f in hookah.db hookah.db-wal hookah.db-shm; do sudo test -e $D/$f && sudo -u hookah mv $D/$f $D/$f.before-restore; done
sudo -u hookah mv $D/restored.db $D/hookah.db
sudo systemctl start hookah-party
```

Номера в копии зашифрованы тем `DATA_KEY`, который действовал в день копии. Если после неё ключ меняли — для этой копии
нужен прежний ключ из `server/data/old-data-key-….env`: временно поставьте его в `.env`, запустите сервер и сразу смените
ключ заново (`server/rotate-key.js`). Старые файлы `*.before-restore` удалите, когда убедитесь, что всё работает.

### Своего человека забанил fail2ban

```bash
sudo fail2ban-client set hookah-party unbanip IP-АДРЕС
```

Сеть IPv6 /64, закрытую вручную (раздел 13), открывают так (вместо примера — сеть из `sudo ufw status`):

```bash
sudo ufw delete deny from 2001:db8:1234:5678::/64 to any app "Nginx Full"
```

Постоянный адрес, который нельзя банить (например, офис), впишите в `ignoreip` в `/etc/fail2ban/jail.d/hookah-party.local`
и выполните `sudo systemctl restart fail2ban`.

### Сервер взломан (чужие процессы, изменённые файлы, странные входы)

Не «чистите» его. Создайте новый сервер по этой инструкции, верните базу из копии вне сервера (шаг 15), смените все ключи и
пароли (раздел про утечку `.env`), старый сервер удалите.

### Перед подключением Cloudflare

Не включайте «оранжевое облако» Cloudflare, пока не поправите nginx: иначе все посетители будут выглядеть как несколько
адресов Cloudflare — лимиты по IP сработают на всех сразу, а fail2ban начнёт банить Cloudflare. Нужно: в `deploy/nginx.conf`
добавить `set_real_ip_from` для сетей Cloudflare и `real_ip_header CF-Connecting-IP;`, а в межсетевом экране оставить
80/443 только для сетей Cloudflare. Попросите разработчика.

## 20. Шпаргалка

| Что | Команда |
|---|---|
| Состояние сайта | `systemctl status hookah-party --no-pager` |
| Журнал сервера | `journalctl -u hookah-party -f` |
| Перезапуск | `sudo systemctl restart hookah-party` |
| Копия сейчас | `sudo systemctl start hookah-backup` |
| Список копий | `sudo ls -l /opt/hookah-party/server/data/backups` |
| Кто в бане | `sudo fail2ban-client status hookah-party` |
| Межсетевой экран | `sudo ufw status verbose` |
| Таймеры (копии, сертификат) | `systemctl list-timers --no-pager` |
| Проверить базу текущим ключом | `cd /opt/hookah-party && sudo -u hookah node server/rotate-key.js --check` |
| Администраторы | `cd /opt/hookah-party && sudo -u hookah node server/admin.js list` |
| Удалить аккаунт по просьбе (войти не может) | `cd /opt/hookah-party && sudo -u hookah node server/admin.js delete +996НОМЕР`, затем то же с `--yes` |
