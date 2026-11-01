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
const PW = 'http://127.0.0.1:3999';
const root = document.getElementById('root');

function guide(msg) {
  root.innerHTML = \`
    <div class="wrap">
      <h1>PortWrench 未运行</h1>
      <p>\${msg}</p>
      <p>PortWrench 是一个独立程序，需要先在你自己的机器上跑起来：</p>
      <ol>
        <li>从 <a href="https://github.com/OldQin-Aurora001/portwrench/releases" target="_blank">GitHub Releases</a> 下载 zip</li>
        <li>解压到任意目录，双击 <code>启动端口控制台.bat</code></li>
        <li>回到这里，点下面这个按钮刷新</li>
      </ol>
      <a class="btn" href="#" onclick="boot();return false;">重新检测</a>
      <p class="muted">仅支持 Windows · Python 3.10+</p>
    </div>\`;
}

async function boot() {
  try {
    const r = await fetch(PW + '/api/v1/health', { mode: 'cors' });
    if (!r.ok) throw new Error('status ' + r.status);
    root.innerHTML = '<iframe src="' + PW + '/" title="PortWrench"></iframe>';
  } catch (e) {
    guide('检测不到本机的 ' + PW + ' 服务。');
  }
}

if (!/Win/i.test(navigator.platform || navigator.userAgent)) {
  root.innerHTML = \`
    <div class="wrap">
      <h1>暂不支持此平台</h1>
      <p>PortWrench 目前仅支持 Windows——它依赖 <code>taskkill</code>、<code>Win32_Process</code> 与 <code>Get-NetTCPConnection</code>。</p>
      <p class="muted">在 Windows 机器上运行 DSH 即可使用本面板。</p>
    </div>\`;
} else {
  boot();
}
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
