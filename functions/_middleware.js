// Middleware de Cloudflare Pages que protege el sitio con una contraseña compartida.
// La contraseña se configura como variable de entorno SITE_PASSWORD en Cloudflare Pages.

const COOKIE_NAME = 'dashboard_auth';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 días
const SALT = 'finanzas-tapi-2026'; // sirve para que la cookie no sea la contraseña en texto plano

async function sha256(text) {
  const buf = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? match[1] : null;
}

function loginPage(errorMessage = '') {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acceso restringido · Dashboard Financiero</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: linear-gradient(135deg, #064e3b 0%, #047857 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 1rem;
  }
  .card {
    background: white;
    padding: 2.5rem 2rem;
    border-radius: 14px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.25);
    max-width: 380px;
    width: 100%;
  }
  .logo { font-size: 2rem; margin-bottom: .5rem; }
  h1 { margin: 0 0 .5rem; font-size: 1.4rem; color: #064e3b; }
  p { margin: 0 0 1.5rem; color: #6b7280; font-size: .9rem; line-height: 1.4; }
  input {
    width: 100%;
    padding: .8rem 1rem;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    font-size: 1rem;
    margin-bottom: 1rem;
    transition: border-color .15s;
  }
  input:focus { outline: none; border-color: #047857; box-shadow: 0 0 0 3px rgba(4,120,87,0.15); }
  button {
    width: 100%;
    padding: .85rem;
    background: #047857;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background .15s;
  }
  button:hover { background: #065f46; }
  .error {
    background: #fef2f2;
    color: #dc2626;
    padding: .65rem .8rem;
    border-radius: 6px;
    font-size: .85rem;
    margin-bottom: 1rem;
    border: 1px solid #fecaca;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">🔒</div>
    <h1>Dashboard Financiero · TAPI</h1>
    <p>Ingresá la contraseña para acceder al dashboard.</p>
    ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}
    <form method="POST" action="/__login">
      <input type="password" name="password" placeholder="Contraseña" autofocus required>
      <button type="submit">Ingresar</button>
    </form>
  </div>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const PASSWORD = env.SITE_PASSWORD;
  if (!PASSWORD) {
    return new Response(
      'Error de configuración: falta la variable de entorno SITE_PASSWORD en Cloudflare Pages.',
      { status: 500 }
    );
  }

  const expectedToken = await sha256(PASSWORD + SALT);

  // 1) Endpoint de login: recibe la contraseña por POST
  if (url.pathname === '/__login' && request.method === 'POST') {
    const form = await request.formData();
    const submitted = form.get('password') || '';

    if (submitted === PASSWORD) {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `${COOKIE_NAME}=${expectedToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE}`
        }
      });
    }

    return new Response(loginPage('Contraseña incorrecta. Intentá de nuevo.'), {
      status: 401,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

  // 2) Si tiene la cookie correcta, lo dejamos pasar
  const cookieValue = getCookie(request, COOKIE_NAME);
  if (cookieValue === expectedToken) {
    return next();
  }

  // 3) Sino, mostramos la pantalla de login
  return new Response(loginPage(), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
