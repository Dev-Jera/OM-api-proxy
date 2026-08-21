# OM API proxy

This proxy is the only public API origin used by browser clients. It injects
`X-API-KEY` server-side for REST and WebSocket requests. Never put the backend
key in `VITE_API_KEY` or any frontend bundle.

Render environment variables:

```text
BACKEND_URL=https://your-backend.onrender.com
BACKEND_API_KEY=<rotated backend API key>
ALLOWED_ORIGINS=https://your-chatbot-domain.com,https://your-admin-domain.com
RATE_LIMIT_PER_MINUTE=120
```

Set each frontend's `VITE_API_BASE_URL` to the proxy origin (for example
`https://om-api-proxy.onrender.com/api/v1`). Remove `VITE_API_KEY` from both
frontends. Do not log request URLs, authorization headers, or API keys.
