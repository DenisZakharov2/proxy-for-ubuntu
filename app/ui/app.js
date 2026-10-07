/* proxy-for-ubuntu — логика GUI.
 *
 * Единственная точка общения с демоном — Tauri-команда `ipc`, формат
 * описан в docs/IPC.md. В браузере (dev-сервер Vite и т.п.) backend
 * недоступен, поэтому подставляется mock с теми же структурами.
 */
'use strict';

// ─────────────────────────────── i18n ──────────────────────────────────────

const I18N = {
  ru: {
    'brand.sub': 'Системный прокси-роутер',
    'nav.overview': 'Обзор', 'nav.proxies': 'Прокси', 'nav.rules': 'Правила',
    'nav.profiles': 'Профили', 'nav.geo': 'Geo-наборы', 'nav.logs': 'Журнал',
    'nav.settings': 'Настройки',
    'action.apply': 'Применить', 'action.toggle': 'Переключить', 'action.cancel': 'Отмена',
    'action.save': 'Сохранить', 'action.delete': 'Удалить', 'action.edit': 'Изменить',
    'action.up': 'Выше', 'action.down': 'Ниже', 'action.close': 'Закрыть', 'action.confirm': 'Подтвердить',
    'status.disconnected': 'Не подключено', 'status.disconnected.sub': 'Трафик идёт напрямую',
    'status.connected': 'Подключено', 'status.connected.sub': 'Весь трафик идёт через прокси по правилам',
    'status.error': 'Ошибка', 'status.error.sub': 'Маршрутизация не работает',
    'chart.total': 'всего',
    'stat.up': 'Отправлено', 'stat.down': 'Получено', 'stat.conns': 'Соединений', 'stat.rules': 'Активных правил',
    'rules.active': 'Куда уходит трафик', 'rules.none': 'Трафика пока нет — подключите прокси',
    'quick.title': 'Быстрые действия', 'quick.addProxy': 'Добавить прокси',
    'quick.addRule': 'Добавить правило', 'quick.doctor': 'Проверить окружение',
    'proxies.title': 'Прокси-серверы', 'proxies.add': 'Добавить', 'proxies.testAll': 'Проверить все',
    'proxies.name': 'Имя', 'proxies.type': 'Тип', 'proxies.address': 'Адрес', 'proxies.status': 'Состояние',
    'proxies.untested': 'не проверен', 'proxies.ok': 'работает', 'proxies.broken': 'не отвечает',
    'rules.title': 'Правила маршрутизации', 'rules.add': 'Добавить правило',
    'rules.validate': 'Проверить конфиг', 'rules.hint': 'Первое совпавшее правило решает. Порядок важен.',
    'rules.kind': 'Условие', 'rules.target': 'Действие', 'rules.valid': 'Конфиг корректен',
    'rules.invalid': 'В конфиге ошибки', 'rules.applied': 'Изменения применены',
    'rules.rolled': 'Изменения не применились, система в прежнем состоянии',
    'profiles.title': 'Профили конфигурации', 'profiles.import': 'Импорт', 'profiles.export': 'Экспорт',
    'profiles.builtin': 'встроенный', 'profiles.active': 'активный',
    'subs.title': 'Подписки', 'subs.name': 'Название', 'subs.url': 'URL', 'subs.update': 'Обновить подписку',
    'geo.title': 'Geo-наборы', 'geo.update': 'Обновить', 'geo.count': 'Записей',
    'geo.updated': 'Обновлён', 'geo.preview': 'Показать',
    'geo.hint': 'Текстовые списки доменов и CIDR. Хранятся в /var/lib/proxy-for-ubuntu/geo.',
    'logs.title': 'Журнал', 'logs.refresh': 'Обновить', 'logs.export': 'Экспорт', 'logs.rollback': 'Откатить конфиг',
    'logs.rollback.confirm': 'Вернуть предыдущую рабочую конфигурацию? Текущие системные правила будут сняты и применены снова.',
    'set.diagnose': 'Проверка окружения', 'set.run': 'Запустить', 'set.interface': 'Интерфейс',
    'set.lang': 'Язык', 'set.theme': 'Тема', 'set.advanced': 'Параметры перехвата',
    'set.diagnose.hint': 'Проверит nftables, TUN, права и занятые порты.',
    'set.intercept.hint': 'fake-ip не допускает утечки DNS, но ломает ping и часть GeoIP-правил. tproxy нужен для QUIC и игр.',
    'err.daemon': 'Демон недоступен', 'err.daemon.hint': 'sudo systemctl start proxy-for-ubuntud',
    'err.generic': 'Что-то пошло не так',
    'err.untouched': 'Системные правила не менялись — откатывать было нечего.',
    'err.rolledBack': 'Системные правила и конфигурация возвращены в прежнее состояние.',
    'err.rollbackFailed': 'Откат не удался: проверьте правила вручную (sudo nft list table inet pfu).', 'err.noProxies': 'Прокси ещё не настроены',
    'err.noProxies.hint': 'Добавьте хотя бы один прокси — иначе весь трафик пойдёт напрямую.',
    'empty.rules': 'Правил нет', 'empty.rules.hint': 'Весь трафик идёт по правилу final',
    'empty.profiles': 'Профилей нет',
    'experimental': 'Не проверен на живом сервере',
    'udp.dnsLeak': 'DNS разрешается локально — есть риск утечки',
    'rule.add': 'Новое правило', 'rule.type': 'Тип условия', 'rule.value': 'Значение', 'rule.policy': 'Действие',
    'save.apply.hint': 'Применение изменит маршрутизацию всей системы. Если что-то пойдёт не так, proxy-for-ubuntu вернёт прежние настройки автоматически.'
  },
  en: {
    'brand.sub': 'System proxy router',
    'nav.overview': 'Overview', 'nav.proxies': 'Proxies', 'nav.rules': 'Rules',
    'nav.profiles': 'Profiles', 'nav.geo': 'Geo sets', 'nav.logs': 'Logs',
    'nav.settings': 'Settings',
    'action.apply': 'Apply', 'action.toggle': 'Toggle', 'action.cancel': 'Cancel',
    'action.save': 'Save', 'action.delete': 'Delete', 'action.edit': 'Edit',
    'action.up': 'Move up', 'action.down': 'Move down', 'action.close': 'Close', 'action.confirm': 'Confirm',
    'status.disconnected': 'Disconnected', 'status.disconnected.sub': 'Traffic goes out directly',
    'status.connected': 'Connected', 'status.connected.sub': 'All traffic goes through the proxy by the rules',
    'status.error': 'Error', 'status.error.sub': 'Routing is not working',
    'chart.total': 'total',
    'stat.up': 'Sent', 'stat.down': 'Received', 'stat.conns': 'Connections', 'stat.rules': 'Active rules',
    'rules.active': 'Where traffic goes', 'rules.none': 'No traffic yet — connect a proxy',
    'quick.title': 'Quick actions', 'quick.addProxy': 'Add a proxy',
    'quick.addRule': 'Add a rule', 'quick.doctor': 'Check environment',
    'proxies.title': 'Proxy servers', 'proxies.add': 'Add', 'proxies.testAll': 'Test all',
    'proxies.name': 'Name', 'proxies.type': 'Type', 'proxies.address': 'Address', 'proxies.status': 'Status',
    'proxies.untested': 'not tested', 'proxies.ok': 'working', 'proxies.broken': 'unreachable',
    'rules.title': 'Routing rules', 'rules.add': 'Add rule',
    'rules.validate': 'Validate config', 'rules.hint': 'The first matching rule wins. Order matters.',
    'rules.kind': 'Condition', 'rules.target': 'Action', 'rules.valid': 'Configuration is valid',
    'rules.invalid': 'Configuration has errors', 'rules.applied': 'Changes applied',
    'rules.rolled': 'Changes were not applied, the system is unchanged',
    'profiles.title': 'Configuration profiles', 'profiles.import': 'Import', 'profiles.export': 'Export',
    'profiles.builtin': 'built-in', 'profiles.active': 'active',
    'subs.title': 'Subscriptions', 'subs.name': 'Name', 'subs.url': 'URL', 'subs.update': 'Update subscription',
    'geo.title': 'Geo sets', 'geo.update': 'Update', 'geo.count': 'Entries',
    'geo.updated': 'Updated', 'geo.preview': 'Show',
    'geo.hint': 'Plain-text domain and CIDR lists, stored in /var/lib/proxy-for-ubuntu/geo.',
    'logs.title': 'Logs', 'logs.refresh': 'Refresh', 'logs.export': 'Export', 'logs.rollback': 'Roll back config',
    'logs.rollback.confirm': 'Restore the previous working configuration? Current system rules will be removed and re-applied.',
    'set.diagnose': 'Environment check', 'set.run': 'Run', 'set.interface': 'Interface',
    'set.lang': 'Language', 'set.theme': 'Theme', 'set.advanced': 'Interception settings',
    'set.diagnose.hint': 'Checks nftables, TUN, privileges and busy ports.',
    'set.intercept.hint': 'fake-ip prevents DNS leaks but breaks ping and some GeoIP rules. tproxy is required for QUIC and games.',
    'err.daemon': 'Daemon unavailable', 'err.daemon.hint': 'sudo systemctl start proxy-for-ubuntud',
    'err.generic': 'Something went wrong',
    'err.untouched': 'System rules were never changed — there was nothing to roll back.',
    'err.rolledBack': 'System rules and configuration were restored to their previous state.',
    'err.rollbackFailed': 'Rollback failed: check the rules manually (sudo nft list table inet pfu).', 'err.noProxies': 'No proxies configured yet',
    'err.noProxies.hint': 'Add at least one proxy, otherwise all traffic goes out directly.',
    'empty.rules': 'No rules', 'empty.rules.hint': 'All traffic follows the final rule',
    'empty.profiles': 'No profiles',
    'experimental': 'Not verified against a live server',
    'udp.dnsLeak': 'DNS is resolved locally — possible leak',
    'rule.add': 'New rule', 'rule.type': 'Condition type', 'rule.value': 'Value', 'rule.policy': 'Action',
    'save.apply.hint': 'Applying will change routing for the entire system. If anything goes wrong, proxy-for-ubuntu restores the previous settings automatically.'
  }
};

const state = {
  lang: localStorage.getItem('pfu.lang') || 'ru',
  theme: localStorage.getItem('pfu.theme') || 'dark',
  route: 'overview',
  config: null,
  metrics: { up: 0, down: 0, connections: 0, active_rules: [] },
  tests: {},           // имя прокси -> {ok, latency_ms}
  nextId: 1,
  connected: false
};

const t = (key) => (I18N[state.lang] && I18N[state.lang][key]) || I18N.ru[key] || key;

// ─────────────────────────────── backend ───────────────────────────────────

const isMock = typeof window.__TAURI__ === 'undefined';

async function ipc(method, params = {}) {
  if (isMock) return mock(method, params);
  const res = await window.__TAURI__.core.invoke('ipc', {
    request: { id: state.nextId++, method, params },
  });
  if (!res.ok) {
    const e = new Error(res.error?.message || t('err.generic'));
    e.code = res.error?.code || 'E_UNKNOWN';
    e.hint = res.error?.hint || null;
    throw e;
  }
  return res.result;
}

/** Mock-демон для разработки интерфейса без рута. */
function mock(method, params) {
  const cfg = state.config || {
    outbounds: [
      { name: 'DIRECT', type: 'direct' },
      { name: 'Мой SOCKS5', type: 'socks5h', server: '1.2.3.4', port: 1080, udp: true, remote_dns: true },
      { name: 'Мой Shadowsocks', type: 'shadowsocks', server: '5.6.7.8', port: 8388, method: 'chacha20-ietf-poly1305', password: 'x', udp: true },
    ],
    rules: [
      'GEOSITE,category-ads-all,REJECT',
      'DOMAIN-SUFFIX,mail.ru,DIRECT',
      'GEOIP,cn,DIRECT',
      'MATCH,Мой SOCKS5',
    ],
    final: 'DIRECT',
    intercept: { tcp: 'redirect', udp: 'tproxy' },
    dns: { strategy: 'fake-ip' },
  };
  switch (method) {
    case 'daemon.status':
      return { daemon: 'running', version: '0.1.0', api: 1, pid: 1, uptime_sec: 120, config_valid: true, enabled: state.connected };
    case 'config.get': return { config: cfg, path: '/etc/proxy-for-ubuntu/config.yaml', is_default: false };
    case 'config.validate': return { valid: true, warnings: [], errors: [] };
    case 'config.apply': return { ok: true, stage: 'done', message: 'applied', rolled_back: false, backup: null, errors: [], warnings: [] };
    case 'config.rollback': return { ok: true, restored_from: '/var/lib/proxy-for-ubuntu/rollback/x.yaml' };
    case 'system.toggle':
      state.connected = params.enabled;
      return { enabled: !!params.enabled, status: params.enabled ? 'connected' : 'disconnected', message: '' };
    case 'metrics.live':
      return {
        up: (state.metrics.up += 178 * 1024), down: (state.metrics.down += 921 * 1024),
        connections: 7, by_outbound: [],
        active_rules: [
          { rule: 'GEOIP,cn', policy: 'DIRECT', bytes: 48 * 1024 * 1024 },
          { rule: 'GEOSITE,category-ads-all', policy: 'REJECT', bytes: 12 * 1024 * 1024 },
          { rule: 'MATCH', policy: 'Мой SOCKS5', bytes: 184 * 1024 * 1024 },
        ],
      };
    case 'outbound.test':
      return { ok: true, latency_ms: 120 + Math.floor(Math.random() * 400), resolved_via: 'remote', error: null };
    case 'geo.list': return { sets: [
      { kind: 'geoip', tag: 'cn', count: 8421, updated_at: 1728200000, source: 'https://…/cn.txt', sha256: 'ab12…' },
      { kind: 'geosite', tag: 'category-ads-all', count: 15234, updated_at: 1728200000, source: 'https://…/ads.txt', sha256: 'cd34…' },
    ] };
    case 'geo.preview': return { lines: ['1.0.1.0/24', '1.0.2.0/23', '1.0.4.0/22'] };
    case 'profile.list': return { profiles: [
      { name: 'default', builtin: true, updated_at: 1728200000 },
      { name: 'Работа', builtin: false, updated_at: 1728261234 },
    ] };
    case 'log.tail': return { entries: [
      { ts: Date.now() / 1000 | 0, level: 'info', target: 'engine::nft', message: 'правила применены' },
      { ts: Date.now() / 1000 | 0, level: 'warn', target: 'engine::geo', message: 'geo-набор cn не скачан' },
    ] };
    case 'system.diagnose': return { checks: [
      { id: 'kernel', name: 'Kernel', ok: true, detail: '6.8.0-generic', fix: null },
      { id: 'nft', name: 'nftables', ok: true, detail: 'v1.0.6', fix: null },
      { id: 'tun', name: 'TUN/TAP', ok: false, detail: 'нет /dev/net/tun', fix: 'sudo modprobe tun' },
      { id: 'root', name: 'Daemon privileges', ok: true, detail: 'root', fix: null },
      { id: 'port-tcp', name: 'TCP redirect port', ok: true, detail: 'порт 15000 свободен', fix: null },
    ], fatal: ['tun'] };
    default: return {};
  }
}

// ─────────────────────────────── утилиты ───────────────────────────────────

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function bytes(n) {
  n = Number(n) || 0;
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n} Б` : `${n.toFixed(1)} ${u[i]}`;
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function when(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString(state.lang === 'ru' ? 'ru-RU' : 'en-US', { dateStyle: 'short', timeStyle: 'short' });
}

function toast(title, body, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<b>${esc(title)}</b>${body ? `<div>${body}</div>` : ''}`;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 250); }, kind === 'err' ? 9000 : 4500);
}

function modal(title, bodyHtml, buttons) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = bodyHtml;
  const foot = $('#modalFoot');
  foot.innerHTML = '';
  for (const b of buttons || []) {
    const el = document.createElement('button');
    el.className = b.kind || 'btn-ghost';
    el.textContent = b.label;
    el.onclick = () => { if (b.action) b.action(); if (b.keepOpen !== true) closeModal(); };
    foot.appendChild(el);
  }
  $('#modalBackdrop').hidden = false;
}
const closeModal = () => { $('#modalBackdrop').hidden = true; };

// ─────────────────────────────── маршрутизация ─────────────────────────────

const ROUTES = {
  overview:  { title: 'nav.overview',  render: renderOverview },
  proxies:   { title: 'nav.proxies',   render: renderProxies },
  rules:     { title: 'nav.rules',     render: renderRules },
  profiles:  { title: 'nav.profiles',  render: renderProfiles },
  geo:       { title: 'nav.geo',       render: renderGeo },
  logs:      { title: 'nav.logs',      render: renderLogs },
  settings:  { title: 'nav.settings',  render: renderSettings },
};

function goto(route) {
  if (!ROUTES[route]) route = 'overview';
  state.route = route;
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.route === route));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${route}`));
  $('#pageTitle').textContent = t(ROUTES[route].title);
  ROUTES[route].render();
}

// ─────────────────────────────── Обзор ─────────────────────────────────────

async function renderOverview() {
  const st = await ipc('daemon.status').catch(() => null);
  const dot = $('#statusDot');
  dot.className = 'status-dot' + (state.connected ? ' on' : '');
  $('#statusTitle').textContent = t(state.connected ? 'status.connected' : 'status.disconnected');
  $('#statusSub').textContent = t(state.connected ? 'status.connected.sub' : 'status.disconnected.sub');
  $('#powerToggle').checked = !!state.connected;
  if (st) {
    const box = $('#daemonState');
    box.classList.add('ok');
    $('#daemonText').textContent = `v${st.version} · ${Math.floor((st.uptime_sec || 0) / 60)} мин`;
  }
  await refreshMetrics();
}

async function refreshMetrics() {
  let m;
  try { m = await ipc('metrics.live'); } catch { return; }
  state.metrics = m;
  $('#trafficChip').hidden = false;
  $('#chipUp').textContent = bytes(m.up);
  $('#chipDown').textContent = bytes(m.down);
  $('#statUp').textContent = bytes(m.up);
  $('#statDown').textContent = bytes(m.down);
  $('#statConns').textContent = m.connections || 0;
  const rows = m.active_rules || [];
  $('#statRules').textContent = rows.length;

  // Кольцевая диаграмма по направлениям.
  const colors = ['#5b8cff', '#8b5cf6', '#34d399', '#fbbf24', '#f87171', '#6b7480'];
  const total = rows.reduce((a, r) => a + (r.bytes || 0), 0);
  if (total > 0) {
    let acc = 0;
    const stops = rows.slice(0, 6).map((r, i) => {
      const from = (acc / total) * 360, to = ((acc + (r.bytes || 0)) / total) * 360;
      acc += r.bytes || 0;
      return `${colors[i % colors.length]} ${from}deg ${to}deg`;
    });
    $('#donut').style.background = `conic-gradient(${stops.join(',')})`;
    $('#donutTotal').textContent = bytes(total);
    $('#donutLegend').innerHTML = rows.slice(0, 6).map((r, i) => `
      <div class="row"><i style="background:${colors[i % colors.length]}"></i>
        <span class="name">${esc(r.policy)}</span>
        <span class="val">${bytes(r.bytes)}</span></div>`).join('');
  } else {
    $('#donutLegend').innerHTML = `<span class="muted">${esc(t('rules.none'))}</span>`;
  }

  const tbl = $('#rulesTraffic');
  if (!rows.length) {
    tbl.innerHTML = `<tbody><tr><td class="empty">${esc(t('rules.none'))}</td></tr></tbody>`;
  } else {
    const max = Math.max(...rows.map(r => r.bytes || 0), 1);
    tbl.innerHTML = `<thead><tr><th>${esc(t('rules.kind'))}</th><th>${esc(t('rules.target'))}</th>
        <th style="text-align:right">${esc(t('chart.total'))}</th></tr></thead><tbody>` +
      rows.map(r => {
        const cls = r.policy === 'REJECT' ? 'reject' : r.policy === 'DIRECT' ? 'direct' : 'proxy';
        return `<tr><td>${esc(r.rule)}</td>
          <td><span class="badge ${cls}">${esc(r.policy)}</span></td>
          <td style="width:40%"><div class="bar" style="width:${Math.round((r.bytes / max) * 100)}%"></div></td>
          <td class="num">${bytes(r.bytes)}</td></tr>`;
      }).join('') + '</tbody>';
  }
}

// ─────────────────────────────── Прокси ────────────────────────────────────

const PROTO_FIELDS = {
  direct: [],
  http: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['username', 'Username', 'text'], ['password', 'Password', 'password']],
  socks: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['username', 'Username', 'text'], ['password', 'Password', 'password'],
          ['udp', 'UDP', 'bool'], ['remote_dns', 'Remote DNS (socks5h)', 'bool']],
  shadowsocks: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['method', 'Method', 'text'], ['password', 'Password', 'password'], ['udp', 'UDP', 'bool']],
  trojan: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['password', 'Password', 'password'], ['sni', 'SNI', 'text'],
           ['skip_cert_verify', 'Skip certificate check', 'bool'], ['udp', 'UDP', 'bool']],
  vless: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['uuid', 'UUID', 'text'], ['sni', 'SNI', 'text'],
          ['tls', 'TLS', 'bool'], ['skip_cert_verify', 'Skip certificate check', 'bool'], ['udp', 'UDP', 'bool']],
  vmess: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['uuid', 'UUID', 'text'], ['alter_id', 'AlterId', 'number'],
          ['sni', 'SNI', 'text'], ['tls', 'TLS', 'bool'], ['skip_cert_verify', 'Skip certificate check', 'bool'], ['udp', 'UDP', 'bool']],
  ssh: [['server', 'Server', 'text'], ['port', 'Port', 'number'], ['username', 'User', 'text'],
        ['key_file', 'Key file', 'text'], ['password', 'Password (or key)', 'password']],
};
const EXPERIMENTAL = new Set(['vless', 'vmess']);

function outbounds() {
  return (state.config && state.config.outbounds) || [];
}

async function renderProxies() {
  const list = outbounds();
  const tbl = $('#proxiesTable');
  if (!list.length) {
    tbl.innerHTML = `<tbody><tr><td class="empty"><div class="big">${esc(t('err.noProxies'))}</div>
      <div>${esc(t('err.noProxies.hint'))}</div></td></tr></tbody>`;
    return;
  }
  tbl.innerHTML = `<thead><tr><th>${esc(t('proxies.name'))}</th><th>${esc(t('proxies.type'))}</th>
      <th>${esc(t('proxies.address'))}</th><th>${esc(t('proxies.status'))}</th><th></th></tr></thead><tbody>` +
    list.map((o, i) => {
      const name = o.name || '—';
      const ty = o.type || '—';
      const addr = o.server ? `${esc(o.server)}:${o.port}` : '—';
      const r = state.tests[name];
      const badge = r
        ? (r.ok ? `<span class="badge ok">${r.latency_ms ?? ''} ${esc(t('proxies.ok'))}</span>`
                 : `<span class="badge reject">${esc(t('proxies.broken'))}</span>`)
        : `<span class="badge">${esc(t('proxies.untested'))}</span>`;
      const exp = EXPERIMENTAL.has(ty) ? ` <span class="badge exp" title="${esc(t('experimental'))}">⚠</span>` : '';
      const leak = (o.type === 'socks' && o.remote_dns === false && o.udp)
        ? `<span class="badge warn" title="${esc(t('udp.dnsLeak'))}">DNS</span>` : '';
      return `<tr>
        <td><b>${esc(name)}</b> ${exp}${leak}</td>
        <td><span class="badge ${ty === 'direct' ? 'direct' : 'proxy'}">${esc(ty)}</span></td>
        <td class="num" style="text-align:left">${addr}</td>
        <td>${badge}</td>
        <td class="actions-cell">
          <button class="btn-ghost sm" data-test="${esc(name)}">${esc(t('proxies.testAll').split(' ')[0])}</button>
          <button class="btn-ghost sm" data-edit="${i}">${esc(t('action.edit'))}</button>
          <button class="btn-danger sm" data-del="${i}">${esc(t('action.delete'))}</button>
        </td></tr>`;
    }).join('') + '</tbody>';

  $$('[data-test]', tbl).forEach(b => b.onclick = () => testOne(b.dataset.test));
  $$('[data-edit]', tbl).forEach(b => b.onclick = () => editProxy(+b.dataset.edit));
  $$('[data-del]', tbl).forEach(b => b.onclick = () => deleteProxy(+b.dataset.del));
}

async function testOne(name) {
  const o = outbounds().find(x => x.name === name);
  if (!o) return;
  toast(name, `${t('proxies.untested')}…`);
  try {
    const r = await ipc('outbound.test', { outbound: o, timeout_ms: 8000 });
    state.tests[name] = r;
    toast(name, r.ok ? `${r.latency_ms} ms · DNS: ${r.resolved_via}` : esc(r.error || ''), r.ok ? 'ok' : 'err');
  } catch (e) {
    state.tests[name] = { ok: false, error: e.message };
    toast(name, esc(e.message), 'err');
  }
  renderProxies();
}

function proxyForm(o = { type: 'direct', name: '' }) {
  const fields = PROTO_FIELDS[o.type] || [];
  return `<div class="form-grid">
    <label><span>${esc(t('proxies.name'))}</span><input id="f-name" value="${esc(o.name || '')}" /></label>
    <label><span>${esc(t('proxies.type'))}</span><select id="f-type">
      ${Object.keys(PROTO_FIELDS).map(k => `<option value="${k}" ${k === o.type ? 'selected' : ''}>${k}</option>`).join('')}
    </select></label>
    ${fields.map(([key, label, type]) => type === 'bool'
      ? `<label class="check full"><input type="checkbox" id="f-${key}" ${o[key] !== false ? 'checked' : ''} /><span>${esc(label)}</span></label>`
      : `<label><span>${esc(label)}</span><input id="f-${key}" type="${type === 'number' ? 'number' : type}" value="${esc(o[key] ?? '')}" /></label>`).join('')}
  </div>
  ${EXPERIMENTAL.has(o.type) ? `<p class="hint" style="color:var(--warn)">⚠ ${esc(t('experimental'))}</p>` : ''}`;
}

function readForm() {
  const type = $('#f-type').value;
  const o = { name: $('#f-name').value.trim(), type };
  for (const [key, , kind] of PROTO_FIELDS[type] || []) {
    const el = $(`#f-${key}`);
    if (!el) continue;
    if (kind === 'bool') o[key] = el.checked;
    else if (kind === 'number') o[key] = el ? Number(el.value) || 0 : 0;
    else o[key] = el.value;
  }
  if (type === 'shadowsocks' && !o.method) o.method = 'chacha20-ietf-poly1305';
  return o;
}

function addProxy() {
  const draw = (cur) => {
    modal(t('proxies.add'), proxyForm(cur), [
      { label: t('action.cancel') },
      { label: t('action.save'), kind: 'btn-primary', action: () => {
          const o = readForm();
          if (!o.name) { toast('—', 'Имя обязательно', 'err'); return; }
          if (EXPERIMENTAL.has(o.type)) { toast('—', t('experimental'), 'warn'); }
          (state.config.outbounds ||= []).push(o);
          renderProxies();
        } },
    ]);
    $('#f-type').onchange = () => draw(readForm());
  };
  draw({ type: 'socks', name: '', udp: true, remote_dns: true });
}

function editProxy(i) {
  const cur = outbounds()[i];
  const draw = (next) => {
    modal(`${t('action.edit')}: ${cur.name}`, proxyForm(next), [
      { label: t('action.cancel') },
      { label: t('action.save'), kind: 'btn-primary', action: () => {
          state.config.outbounds[i] = readForm();
          renderProxies();
        } },
    ]);
    $('#f-type').onchange = () => draw(readForm());
  };
  draw({ ...cur });
}

function deleteProxy(i) {
  const o = outbounds()[i];
  if (!o) return;
  if (o.name === 'DIRECT') { toast('—', 'DIRECT удалить нельзя', 'err'); return; }
  modal(t('action.delete'), `<p>${esc(t('action.delete'))} «${esc(o.name)}»?</p>`, [
    { label: t('action.cancel') },
    { label: t('action.delete'), kind: 'btn-danger', action: () => {
        state.config.outbounds.splice(i, 1);
        renderProxies();
      } },
  ]);
}

// ─────────────────────────────── Правила ───────────────────────────────────

const RULE_KINDS = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'IP-CIDR',
                    'GEOIP', 'GEOSITE', 'DST-PORT', 'SRC-PORT', 'PROCESS-NAME', 'UID', 'NETWORK', 'MATCH'];
const KIND_LABEL = {
  'DOMAIN': 'домен целиком', 'DOMAIN-SUFFIX': 'суффикс домена', 'DOMAIN-KEYWORD': 'подстрока домена',
  'DOMAIN-REGEX': 'регулярное выражение', 'IP-CIDR': 'адрес или подсеть', 'GEOIP': 'geoip-набор',
  'GEOSITE': 'geosite-набор', 'DST-PORT': 'порт назначения', 'SRC-PORT': 'порт источника',
  'PROCESS-NAME': 'имя процесса', 'UID': 'uid пользователя', 'NETWORK': 'tcp или udp', 'MATCH': 'всё остальное',
};
const policyClass = (p) =>
  p === 'REJECT' || p === 'REJECT-DROP' ? 'reject' : p === 'DIRECT' ? 'direct' : 'proxy';

function rules() {
  return (state.config && state.config.rules) || [];
}
const ruleRaw = (r) => (typeof r === 'string' ? r : (r && r.raw) || '');

async function renderRules() {
  const list = rules();
  const tbl = $('#rulesTable');
  if (!list.length) {
    tbl.innerHTML = `<tbody><tr><td class="empty"><div class="big">${esc(t('empty.rules'))}</div>
      <div>${esc(t('empty.rules.hint'))}</div></td></tr></tbody>`;
    return;
  }
  tbl.innerHTML = `<thead><tr><th>#</th><th>${esc(t('rules.kind'))}</th><th>${esc(t('rules.target'))}</th><th></th></tr></thead><tbody>` +
    list.map((r, i) => {
      const raw = ruleRaw(r);
      const parts = raw.split(',');
      const kind = parts[0] || '';
      const arg = parts.length > 2 ? parts.slice(1, -1).join(',') : '';
      const policy = parts[parts.length - 1] || '';
      return `<tr>
        <td class="idx">${i + 1}</td>
        <td><b>${esc(kind)}</b> ${arg ? `<span class="muted">${esc(arg)}</span>` : ''}
            <div class="muted" style="font-size:11.5px">${esc(KIND_LABEL[kind] || '')}</div></td>
        <td><span class="badge ${policyClass(policy)}">${esc(policy)}</span></td>
        <td class="actions-cell">
          <button class="btn-ghost sm" data-up="${i}" title="${esc(t('action.up'))}">↑</button>
          <button class="btn-ghost sm" data-down="${i}" title="${esc(t('action.down'))}">↓</button>
          <button class="btn-ghost sm" data-rm="${i}">${esc(t('action.delete'))}</button>
        </td></tr>`;
    }).join('') +
    `<tr><td></td><td class="muted">${esc(t('empty.rules.hint').replace('^.*final.*$', ''))}</td>
      <td><span class="badge direct">${esc((state.config && state.config.final) || 'DIRECT')}</span></td><td></td></tr></tbody>`;

  $$('[data-up]', tbl).forEach(b => b.onclick = () => move(+b.dataset.up, -1));
  $$('[data-down]', tbl).forEach(b => b.onclick = () => move(+b.dataset.down, 1));
  $$('[data-rm]', tbl).forEach(b => b.onclick = () => { state.config.rules.splice(+b.dataset.rm, 1); renderRules(); });
}

function move(i, d) {
  const j = i + d;
  const list = state.config.rules;
  if (j < 0 || j >= list.length) return;
  [list[i], list[j]] = [list[j], list[i]];
  renderRules();
}

function addRule() {
  const policies = outbounds().map(o => o.name).concat(['DIRECT', 'REJECT', 'REJECT-DROP', 'HIJACK-DNS']);
  modal(t('rule.add'), `<div class="form-grid">
      <label><span>${esc(t('rule.type'))}</span><select id="r-kind">
        ${RULE_KINDS.map(k => `<option value="${k}">${k} — ${esc(KIND_LABEL[k])}</option>`).join('')}
      </select></label>
      <label><span>${esc(t('rule.value'))}</span><input id="r-value" placeholder="example.com" /></label>
      <label class="grow"><span>${esc(t('rule.policy'))}</span><select id="r-policy">
        ${[...new Set(policies)].map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('')}
      </select></label>
    </div>`, [
    { label: t('action.cancel') },
    { label: t('action.save'), kind: 'btn-primary', action: () => {
        const kind = $('#r-kind').value;
        const val = $('#r-value').value.trim();
        const pol = $('#r-policy').value;
        if (kind !== 'MATCH' && !val) { toast('—', 'Значение обязательно', 'err'); return; }
        (state.config.rules ||= []).push(kind === 'MATCH' ? `MATCH,${pol}` : `${kind},${val},${pol}`);
        renderRules();
      } },
  ]);
  $('#r-kind').onchange = () => {
    const k = $('#r-kind').value;
    $('#r-value').disabled = k === 'MATCH';
    if (k === 'MATCH') $('#r-value').value = '';
  };
}

async function validateRules() {
  try {
    const r = await ipc('config.validate', { config: state.config });
    if (r.valid) {
      toast(t('rules.valid'), (r.warnings || []).map(esc).join('<br>') || '', r.warnings && r.warnings.length ? 'warn' : 'ok');
    } else {
      toast(t('rules.invalid'), (r.errors || []).map(e => esc(e.message)).join('<br>'), 'err');
    }
  } catch (e) {
    toast(t('rules.invalid'), esc(e.message), 'err');
  }
}

// ─────────────────────────────── Профили ───────────────────────────────────

async function renderProfiles() {
  const r = await ipc('profile.list').catch(() => ({ profiles: [] }));
  const tbl = $('#profilesTable');
  const list = r.profiles || [];
  if (!list.length) {
    tbl.innerHTML = `<tbody><tr><td class="empty">${esc(t('empty.profiles'))}</td></tr></tbody>`;
    return;
  }
  tbl.innerHTML = `<thead><tr><th>${esc(t('proxies.name'))}</th><th>${esc(t('proxies.status'))}</th><th></th></tr></thead><tbody>` +
    list.map(p => `<tr><td>${esc(p.name)} ${p.builtin ? `<span class="badge">${esc(t('profiles.builtin'))}</span>` : ''}</td>
      <td class="muted">${when(p.updated_at)}</td>
      <td class="actions-cell"><button class="btn-primary sm" data-act="${esc(p.name)}">${esc(t('rule.policy'))}</button></td></tr>`).join('') +
    '</tbody>';
  $$('[data-act]', tbl).forEach(b => b.onclick = () => activateProfile(b.dataset.act));
}

async function activateProfile(name) {
  try {
    const r = await ipc('profile.activate', { name });
    if (r.ok) { await loadConfig(); toast(t('rules.applied'), esc(name), 'ok'); goto(state.route); }
    else toast(t('rules.rolled'), '', 'err');
  } catch (e) { toast(t('rules.rolled'), esc(e.message), 'err'); }
}

async function importProfile() {
  modal(t('profiles.import'), `<div class="form-grid">
      <label class="full"><span>YAML</span><textarea id="i-yaml" rows="12" placeholder="outbounds: …"></textarea></label>
      <label><span>${esc(t('subs.name'))}</span><input id="i-name" value="imported" /></label>
    </div>`, [
    { label: t('action.cancel') },
    { label: t('action.save'), kind: 'btn-primary', action: async () => {
        try {
          await ipc('profile.import', { name: $('#i-name').value.trim() || 'imported', yaml: $('#i-yaml').value });
          toast(t('profiles.import'), 'ok', 'ok');
          renderProfiles();
        } catch (e) { toast(t('rules.invalid'), esc(e.message), 'err'); }
      } },
  ]);
}

async function exportProfile() {
  try {
    const r = await ipc('profile.export', { name: 'default', redact_secrets: true });
    modal(t('profiles.export'), `<textarea rows="16" style="width:100%">${esc(r.yaml || '')}</textarea>
      <p class="hint">${esc(t('empty.rules.hint') ? 'Секреты заменены на ***REDACTED***' : '')}</p>`,
      [{ label: t('action.close') }]);
  } catch (e) { toast(t('err.generic'), esc(e.message), 'err'); }
}

// ─────────────────────────────── Geo ───────────────────────────────────────

async function renderGeo() {
  const r = await ipc('geo.list').catch(() => ({ sets: [] }));
  const tbl = $('#geoTable');
  const list = r.sets || [];
  if (!list.length) {
    tbl.innerHTML = `<tbody><tr><td class="empty">Нет наборов. Добавьте источники в <code>geo.sources</code> конфигурации.</td></tr></tbody>`;
    return;
  }
  tbl.innerHTML = `<thead><tr><th>Тип</th><th>Тег</th><th>${esc(t('geo.count'))}</th><th>${esc(t('geo.updated'))}</th><th></th></tr></thead><tbody>` +
    list.map(s => `<tr><td><span class="badge ${s.kind === 'geoip' ? 'proxy' : 'direct'}">${esc(s.kind)}</span></td>
      <td>${esc(s.tag)}</td><td class="num">${s.count}</td><td class="muted">${when(s.updated_at)}</td>
      <td class="actions-cell"><button class="btn-ghost sm" data-kind="${s.kind}" data-tag="${esc(s.tag)}">${esc(t('geo.preview'))}</button></td></tr>`).join('') +
    '</tbody>';
  $$('[data-tag]', tbl).forEach(b => b.onclick = async () => {
    const r2 = await ipc('geo.preview', { kind: b.dataset.kind, tag: b.dataset.tag, limit: 200 }).catch(() => ({ lines: [] }));
    modal(`${b.dataset.kind}:${b.dataset.tag}`, `<pre class="log">${esc((r2.lines || []).join('\n'))}</pre>`,
          [{ label: t('action.close') }]);
  });
}

// ─────────────────────────────── Журнал ────────────────────────────────────

async function renderLogs() {
  const lvl = $('#logLevel').value;
  const r = await ipc('log.tail', { lines: 500, level: lvl || null }).catch(() => ({ entries: [] }));
  const rows = r.entries || [];
  $('#logView').textContent = rows.length
    ? rows.map(e => `[${when(e.ts)}] ${e.level.toUpperCase().padEnd(5)} ${e.target}: ${e.message}`).join('\n')
    : 'Журнал пуст.';
}

// ─────────────────────────────── Настройки ─────────────────────────────────

async function renderSettings() {
  const c = state.config || {};
  $('#tcpMode').value = (c.intercept && c.intercept.tcp) || 'redirect';
  $('#udpMode').value = (c.intercept && c.intercept.udp) || 'tproxy';
  $('#dnsStrategy').value = (c.dns && c.dns.strategy) || 'fake-ip';
  $('#langSelect').value = state.lang;
  $('#themeSelect').value = state.theme;
}

async function runDoctor() {
  const view = $('#doctorView');
  view.innerHTML = '<p class="muted">…</p>';
  try {
    const r = await ipc('system.diagnose');
    view.innerHTML = (r.checks || []).map(c => `
      <div class="check-row ${c.ok ? 'ok' : 'bad'}">
        <span class="mark">${c.ok ? '✓' : '✕'}</span>
        <span class="name">${esc(c.name)}</span>
        <span class="detail">${esc(c.detail || '')}
          ${c.fix ? `<span class="fix">${esc(c.fix)}</span>` : ''}</span>
      </div>`).join('') +
      (r.fatal && r.fatal.length
        ? `<p class="hint" style="color:var(--err);margin-top:10px">Критичные проблемы: ${esc(r.fatal.join(', '))}</p>`
        : `<p class="hint" style="color:var(--ok);margin-top:10px">Всё в порядке.</p>`);
  } catch (e) {
    view.innerHTML = `<p class="hint" style="color:var(--err)">${esc(e.message)}</p>`;
  }
}

// ─────────────────────────────── применение ────────────────────────────────

async function applyConfig() {
  const names = outbounds().filter(o => o.name !== 'DIRECT');
  if (!names.length) { toast(t('err.noProxies'), esc(t('err.noProxies.hint')), 'warn'); return; }

  modal(t('action.apply'), `<p>${esc(t('save.apply.hint'))}</p>`, [
    { label: t('action.cancel') },
    { label: t('action.confirm'), kind: 'btn-primary', action: doApply },
  ]);
  // Кнопка в модальном окне уже показывает подтверждение — отдельного
  // confirm() не нужно: пользователь видит ровно то, что изменится.
}

async function doApply() {
  try {
    const r = await ipc('config.apply', { config: state.config, reason: 'gui' });
    if (r.ok) {
      toast(t('rules.applied'), (r.warnings || []).map(esc).join('<br>'), (r.warnings || []).length ? 'warn' : 'ok');
      await loadConfig();
    } else {
      // Три разных исхода, и путать их нельзя: на validate/probe система
      // не тронута, на commit+health-check откат выполняется, а если
      // откат не сработал — это совсем другая история и ручное вмешательство.
      let note;
      if (!r.system_touched) {
        note = t('err.untouched');
      } else if (r.rolled_back) {
        note = t('err.rolledBack');
      } else {
        note = t('err.rollbackFailed');
      }
      toast(t('rules.rolled'), `<b>${esc(r.stage || '')}</b><br>${esc(r.message || '')}` +
        (r.errors || []).map(e => `<br>· ${esc(e)}`).join('') +
        `<br><br>${esc(note)}`, 'err');
    }
    renderOverview();
  } catch (e) {
    toast(t('status.error'), esc(e.message) + (e.hint ? `<br><span class="hint">${esc(e.hint)}</span>` : ''), 'err');
  }
}

async function togglePower(on) {
  try {
    const r = await ipc('system.toggle', { enabled: on });
    state.connected = !!r.enabled;
    renderOverview();
    toast(r.enabled ? t('status.connected') : t('status.disconnected'), '', r.enabled ? 'ok' : '');
  } catch (e) {
    state.connected = false;
    $('#powerToggle').checked = false;
    toast(t('status.error'), esc(e.message) + (e.hint ? `<br><span class="hint">${esc(e.hint)}</span>` : ''), 'err');
  }
}

// ─────────────────────────────── тема и язык ───────────────────────────────

function applyTheme() {
  const sys = window.matchMedia('(prefers-color-scheme: light)').matches;
  document.documentElement.dataset.theme =
    state.theme === 'auto' ? (sys ? 'light' : 'dark') : state.theme;
  localStorage.setItem('pfu.theme', state.theme);
}
function applyLang() {
  document.documentElement.lang = state.lang;
  $$('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  localStorage.setItem('pfu.lang', state.lang);
  $('#pageTitle').textContent = t(ROUTES[state.route].title);
}

// ─────────────────────────────── загрузка ──────────────────────────────────

async function loadConfig() {
  try {
    const r = await ipc('config.get');
    state.config = r.config;
  } catch (e) {
    state.config = null;
    toast(t('err.daemon'), esc(e.message) + `<br><span class="hint">${esc(t('err.daemon.hint'))}</span>`, 'err');
    $('#daemonState').classList.add('bad');
    $('#daemonText').textContent = t('err.daemon');
  }
}

async function boot() {
  applyTheme();
  applyLang();
  await loadConfig();

  $('#nav').onclick = e => {
    const b = e.target.closest('.nav-item');
    if (b) goto(b.dataset.route);
  };
  $('#modalClose').onclick = closeModal;
  $('#modalBackdrop').onclick = e => { if (e.target === $('#modalBackdrop')) closeModal(); };
  $('#themeToggle').onclick = () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    applyTheme();
  };
  $('#langSelect').onchange = e => { state.lang = e.target.value; applyLang(); renderOverview(); };
  $('#themeSelect').onchange = e => { state.theme = e.target.value; applyTheme(); };
  $('#powerToggle').onchange = e => togglePower(e.target.checked);
  $('#applyBtn').onclick = applyConfig;
  $('#addProxy').onclick = addProxy;
  $('#addRule').onclick = addRule;
  $('#validateRules').onclick = validateRules;
  $('#importProfile').onclick = importProfile;
  $('#exportProfile').onclick = exportProfile;
  $('#runDoctor').onclick = runDoctor;
  $('#refreshLogs').onclick = renderLogs;
  $('#logLevel').onchange = renderLogs;
  $('#testAll').onclick = async () => {
    for (const o of outbounds()) if (o.name !== 'DIRECT') await testOne(o.name);
  };
  $('#geoUpdate').onclick = async () => {
    toast(t('geo.update'), '…');
    renderGeo();
  };
  $('#exportLogs').onclick = async () => {
    const r = await ipc('log.export', {});
    toast(t('logs.export'), esc(r.path || ''), 'ok');
  };
  $('#rollback').onclick = () => modal(t('logs.rollback'), `<p>${esc(t('logs.rollback.confirm'))}</p>`, [
    { label: t('action.cancel') },
    { label: t('action.confirm'), kind: 'btn-danger', action: async () => {
        const r = await ipc('config.rollback');
        toast(r.ok ? t('logs.rollback') : t('err.generic'), esc(r.restored_from || r.message || ''), r.ok ? 'ok' : 'err');
        await loadConfig(); renderOverview();
      } },
  ]);
  $('#subUpdate').onclick = async () => {
    try {
      const r = await ipc('subscription.update', {
        name: $('#subName').value.trim() || 'subscription', url: $('#subUrl').value.trim(), auto_activate: false,
      });
      toast(t('subs.update'), `outbound: ${r.outbounds_found}, правил: ${r.rules_found}`, 'ok');
      renderProfiles();
    } catch (e) { toast(t('err.generic'), esc(e.message), 'err'); }
  };
  for (const [id, key] of [['tcpMode', 'tcp'], ['udpMode', 'udp'], ['dnsStrategy', 'strategy']]) {
    $(`#${id}`).onchange = e => {
      if (!state.config) return;
      (state.config.intercept ||= {})[key] = e.target.value;
      if (id === 'dnsStrategy') (state.config.dns ||= {}).strategy = e.target.value;
    };
  }
  $$('[data-goto]').forEach(b => b.onclick = () => goto(b.dataset.goto));

  goto('overview');
  setInterval(() => { if (state.route === 'overview') refreshMetrics(); }, 2000);
}

document.addEventListener('DOMContentLoaded', boot);
