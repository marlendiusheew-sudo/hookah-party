#!/usr/bin/env bash
# Межсетевой экран ufw для сервера Hookah Party (Ubuntu 24.04). Запускать повторно можно — результат тот же.
#   sudo bash deploy/firewall.sh
# Входящие соединения: только SSH (с ограничением частоты: 6 подключений за 30 секунд с одного IP), 80 и 443.
# Исходящие — все (обновления, SMS-шлюз, Let's Encrypt). Порт Node (3000) снаружи закрыт: к нему ходит только nginx.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "Запустите через sudo: sudo bash deploy/firewall.sh" >&2; exit 1; fi
if ! command -v ufw >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq ufw; fi

# Порт SSH берём из настроек sshd, чтобы не закрыть себе вход, если он не 22.
ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u || true)
[ -n "$ssh_ports" ] || ssh_ports=22

# Сначала правило для SSH, потом запрет по умолчанию: даже если ufw уже был включён, вход не пропадёт ни на миг.
for p in $ssh_ports; do
  if [ "$p" = 22 ] && ufw app info OpenSSH >/dev/null 2>&1; then ufw limit OpenSSH; else ufw limit "$p/tcp"; fi
done
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

if grep -q '^IPV6=no' /etc/default/ufw 2>/dev/null; then
  echo "Внимание: в /etc/default/ufw стоит IPV6=no — IPv6 не фильтруется. Если у сервера есть IPv6, поставьте IPV6=yes и запустите скрипт снова."
fi
ufw status verbose
