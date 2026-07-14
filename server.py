from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

MESSAGES = []
HOST_PASSWORD = "host123"

HTML_PAGE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Broadcast Feed</title>
  <script>
    function refreshMessages() {
      fetch('/').then(response => response.text()).then(html => {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const newHistory = doc.querySelector('.history');
        const currentHistory = document.querySelector('.history');
        if (newHistory && currentHistory) {
          currentHistory.innerHTML = newHistory.innerHTML;
        }
      }).catch(err => console.log('Refresh failed', err));
    }

    setInterval(refreshMessages, 2000);
  </script>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #0f172a;
      color: #e5eefc;
      font-family: Arial, sans-serif;
    }
    .app {
      max-width: 560px;
      margin: 0 auto;
      padding: 16px;
    }
    h2 {
      margin: 0 0 12px;
      font-size: 1.2rem;
      color: #f8fafc;
    }
    .hint {
      color: #94a3b8;
      margin: 0 0 12px;
    }
    .history {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 12px;
      min-height: 300px;
      max-height: 60vh;
      overflow-y: auto;
      margin-bottom: 12px;
    }
    .msg {
      background: #1e293b;
      padding: 10px 12px;
      border-radius: 10px;
      margin-bottom: 8px;
      word-break: break-word;
    }
    .msg small {
      display: block;
      color: #94a3b8;
      margin-bottom: 4px;
      font-size: 0.75rem;
    }
    .actions {
      display: flex;
      justify-content: flex-end;
    }
    a {
      color: #60a5fa;
      text-decoration: none;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="app">
    <h2>Broadcast Feed</h2>
    <p class="hint">Only the host can publish announcements. Users can read the latest updates here.</p>
    <div class="history">
      {% for msg in messages %}
        <div class="msg">{{ msg }}</div>
      {% else %}
        <div class="msg"><small>No broadcast messages yet</small></div>
      {% endfor %}
    </div>
    <div class="actions">
      <a href="/host">Open host panel</a>
    </div>
  </div>
</body>
</html>
'''

HOST_PAGE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Host Broadcast Panel</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #020617;
      color: #e2e8f0;
      font-family: Arial, sans-serif;
    }
    .app {
      max-width: 560px;
      margin: 0 auto;
      padding: 24px 16px;
    }
    h2 {
      margin: 0 0 8px;
      font-size: 1.2rem;
      color: #f8fafc;
    }
    p {
      color: #94a3b8;
      margin: 0 0 16px;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      margin-bottom: 12px;
    }
    input {
      padding: 0.8rem;
      border-radius: 10px;
      border: 1px solid #334155;
      background: #0f172a;
      color: #e5eefc;
      outline: none;
    }
    button {
      padding: 0.8rem 1rem;
      border: 0;
      border-radius: 10px;
      background: #16a34a;
      color: white;
      font-weight: bold;
      cursor: pointer;
    }
    a {
      color: #60a5fa;
      text-decoration: none;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="app">
    <h2>Host Broadcast Panel</h2>
    <p>Use this page to send a message to all users. Only the host can publish.</p>
    <form method="POST" action="/broadcast">
      <input type="password" name="host_password" placeholder="Host password" autocomplete="off" required>
      <input name="message" placeholder="Type a broadcast message" autocomplete="off" required>
      <button type="submit">Broadcast</button>
    </form>
    <a href="/">Back to user view</a>
  </div>
</body>
</html>
'''


@app.route('/')
def home():
    return render_template_string(HTML_PAGE, messages=MESSAGES)


@app.route('/host')
def host():
    return render_template_string(HOST_PAGE)


@app.route('/broadcast', methods=['POST'])
def broadcast():
    host_password = request.form.get('host_password', '').strip()
    message = request.form.get('message', '').strip()

    if host_password == HOST_PASSWORD and message:
        MESSAGES.append(f"[HOST] {message}")
        print(f"\n📢 Broadcast from host: {message}\n")
    else:
        print("\n⚠️ Rejected broadcast attempt\n")

    return redirect(url_for('host'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
