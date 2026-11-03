// DSH 后端半边：注册一个 /portwrench 路由，返回壳的页面。
// 注意：id 必须等于 npm 包名，否则服务端全好、前端白屏。

const PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>PortWrench</title>
  <style>
    html,body{margin:0;height:100%;font-family:system-ui,sans-serif;background:#fafafa}
    iframe{width:100%;height:100%;border:0}
    .wrap{max-width:640px;margin:60px auto;padding:0 24px;line-height:1.8;color:#222}
    h1{font-size:20px;margin:0 0 16px}
    .btn{display:inline-block;padding:10px 18px;background:#1a73e8;color:#fff;
         text-decoration:none;border-radius:6px;margin:16px 0}
    code{background:#eee;padding:2px 6px;border-radius:4px}
    .muted{color:#666;font-size:14px}
  </style>
</head>
<body>
<div id="root"></div>
<script>
// 本体只绑回环，默认 3999；被占则顺延（port_console.PORT_SCAN_RANGE=100，末位 4098）。
// 壳不再硬编码单地址：并发探活整个顺延区间，取最低响应端口——与本体
// "从 3999 起取第一个可绑定端口" 的实例选择结果一致。
var PW_BASE = 3999;
var PW_MAX = 4098;                 // 必须等于 DEFAULT_PORT + PORT_SCAN_RANGE - 1
var PROBE_TIMEOUT_MS = 800;        // 单口探活上限；回环拒连通常立即返回
var root = document.getElementById('root');

function showDetecting(msg) {
  root.innerHTML =
    '<div class="wrap"><h1>正在检测本机 PortWrench…</h1><p>' + msg + '</p></div>';
}

function probe(port) {
  var ctrl = new AbortController();
  var timer = setTimeout(function () { ctrl.abort(); }, PROBE_TIMEOUT_MS);
  return fetch('http://127.0.0.1:' + port + '/api/v1/health',
               { mode: 'cors', signal: ctrl.signal })
    .then(function (r) {
      if (!r.ok) { clearTimeout(timer); return 0; }
      // 1.2 改-10（M-06 净增量）：必须响应体是本体的 health，不能只看状态码。
      // 3999-4098 是本体顺延区间，这一段里任何 dev server / 别的服务的 200
      // 都会被旧逻辑（只判 r.ok）当成 PortWrench 嵌进来——错认人。
      // 本体 health 必带 ok:true + api_version:"v1"；非 JSON / 字段不符一律按未命中。
      return r.json().then(function (j) {
        clearTimeout(timer);
        return (j && j.ok === true && j.api_version === 'v1') ? port : 0;
      }).catch(function () { clearTimeout(timer); return 0; });
    })
    .catch(function () { clearTimeout(timer); return 0; });
}

function discover() {
  var ports = [];
  for (var p = PW_BASE; p <= PW_MAX; p++) ports.push(p);
  return Promise.all(ports.map(probe)).then(function (results) {
    for (var i = 0; i < results.length; i++) {
      if (results[i] > 0) return results[i];   // 最低端口 = 本体实际实例
    }
    return 0;
  });
}

function embed(port) {
  root.innerHTML = '<iframe src="http://127.0.0.1:' + port + '/" title="PortWrench"></iframe>';
}

function guide(msg) {
  root.innerHTML = \`
    <div class="wrap">
      <h1>PortWrench 未运行</h1>
      <p>\${msg}</p>
      <p>已自动探测本机 \${PW_BASE}–\${PW_MAX}（与本体端口顺延范围一致），没有发现在线实例。</p>
      <p>PortWrench 是一个独立程序，需要先在你自己的机器上跑起来：</p>
      <ol>
        <li>从 <a href="https://github.com/OldQin-Aurora001/portwrench/releases" target="_blank">GitHub Releases</a> 下载 zip</li>
        <li>解压到任意目录，双击 <code>启动端口控制台.bat</code></li>
        <li>回到这里，点下面这个按钮重新检测</li>
      </ol>
      <a class="btn" href="#" onclick="boot();return false;">重新检测</a>
      <p class="muted">仅支持 Windows · Python 3.10+</p>
    </div>\`;
}

function boot() {
  if (!/Win/i.test(navigator.platform || navigator.userAgent)) {
    root.innerHTML = \`
    <div class="wrap">
      <h1>暂不支持此平台</h1>
      <p>PortWrench 目前仅支持 Windows——它依赖 <code>taskkill</code>、<code>Win32_Process</code> 与 <code>Get-NetTCPConnection</code>。</p>
      <p class="muted">在 Windows 机器上运行 DSH 即可使用本面板。</p>
    </div>\`;
    return;
  }
  showDetecting('正在并发探测 ' + PW_BASE + '–' + PW_MAX + ' …');
  discover().then(function (port) {
    if (port) { embed(port); return; }
    guide('检测不到任何本机 PortWrench 服务。');
  }).catch(function (e) {
    guide('检测过程出错：' + ((e && e.message) ? e.message : e));
  });
}

boot();
</script>
</body>
</html>`;

export function apply(ctx) {
  const webServer = ctx.get('webServer');
  if (!webServer) return;

  const dispose = webServer.register({
    kind: 'exact',
    path: '/portwrench',
    handler(req, res) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      });
      res.end(PAGE_HTML);
    },
  });

  return () => { try { dispose(); } catch (_) {} };
}
