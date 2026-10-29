# Docker TCP: проверка перехвата

Проверялось на 0.1.2 (debug-демон), конфиг с `intercept.docker: true`.

## Подготовка

```bash
cp /etc/proxy-for-ubuntu/config.yaml orig.yaml
# добавить в секцию intercept строку:
#   docker: true
systemd-run --system --wait --collect --unit=pfu-cfg-put \
  /bin/sh -c 'install -m 640 -o root -g proxy-for-ubuntu docker.yaml /etc/proxy-for-ubuntu/config.yaml'
systemd-run --system --unit=pfu-devd --property=Restart=no --property=LimitNOFILE=65536 \
  <clone>/app/src-tauri/target/debug/proxy-for-ubuntud --daemon
./target/debug/pfu-cli connect
```

## Проверка

```bash
nft list table inet pfu | grep -A6 nat_prerouting   # цепочка есть
docker pull -q curlimages/curl
./target/debug/pfu-cli metrics                      # до
docker run --rm curlimages/curl -s -m 15 https://ifconfig.me
./target/debug/pfu-cli metrics                      # счётчики выросли

# во время запроса видно соединение контейнера в слушателе демона:
(docker run --rm curlimages/curl -s -m 20 -o /dev/null https://speed.hetzner.de/100MB.bin &)
sleep 3
ss -tn state established '( sport = :15000 )'
# 127.0.0.1:15000   192.168.10.96:<эфемерный>   ← адрес контейнера
```

## Уборка и возврат конфига

```bash
./target/debug/pfu-cli disconnect
systemd-run --system --wait --collect --unit=pfu-cfg-back \
  /bin/sh -c 'cp orig.yaml /etc/proxy-for-ubuntu/config.yaml && chown root:proxy-for-ubuntu /etc/proxy-for-ubuntu/config.yaml && chmod 640 /etc/proxy-for-ubuntu/config.yaml'
systemctl stop pfu-devd
```

Проверено: правила снимаются, порты закрыты, конфиг без `docker: true`, сеть и контейнеры работают.
UDP из контейнера не проверялся: нужен эхо-сервер, доступный по маршруту (не через `lo`).
