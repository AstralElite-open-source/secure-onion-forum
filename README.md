# Onion Forum

Lightweight, login-protected forum for Tor. Fast to deploy, minimal dependencies, and ready as a v3 onion service.

## Features

- Zero JavaScript by default, server‑rendered UI
- Posts + comments, pagination, categories
- Safe Markdown rendering (sanitized), CSRF protection, strict CSP
- SQLite storage (single file), tiny resource usage
- One‑step Docker with a built‑in Tor hidden service
- Login system (required by default) with admin‑managed users
	- Usernames are encrypted at rest; passwords are hashed (never stored in plaintext)

## Requirements

- Docker Desktop (Windows/macOS) or Docker Engine + Compose (Linux)

## Quick start (2 commands)

1. Start services (web + tor):

```bash
docker compose up --build -d
```

1. After ~60 seconds, print the onion address:

```bash
docker compose exec tor sh -lc 'cat /var/lib/tor/hidden_service/hostname'
```

That’s it. The forum is available over your .onion address (port 80).

Next, visit your onion URL and go to /login to create the first admin account. Once logged in as admin, use /admin/users to add more users.

## Stop / reset

- Stop: `docker compose down`
- Reset data (removes all posts and regenerates the onion address):

```bash
docker compose down
docker volume rm onion_forum_data 
docker volume rm onion_tor_data
```

## Data & persistence

- Forum data (SQLite DB) and the app’s secret key live in the `forum_data` volume at `/data` inside the container.
- Tor hidden service keys and `hostname` live in the `tor_data` volume.
- A persistent SECRET_KEY is auto‑generated on first run and stored at `/data/secret_key` (no setup needed). You can still override with an environment variable if you prefer.


## Health check

The app exposes `GET /healthz` for a quick check. Example:

```bash
curl http://localhost:8080/healthz
```

## Configuration (optional)

Environment variables you can set (Compose reads from your shell or a local `.env` file):

- `REQUIRE_LOGIN`: set to `0` to disable login requirement (default: `1`).
- `ADMIN_USER` and `ADMIN_PASS`: optionally pre-create an admin user on first boot.
- `SECRET_KEY`: override the auto‑generated key with your own 64‑hex string.
- `FORUM_DB_PATH`: path to the SQLite DB file (default: `/data/forum.db`).
- `PORT`: internal web port (default: 8080).

## Login & Admin

- Login is required by default. First visit to `/login` will bootstrap the very first admin account.
- After that, sign in and visit `/admin/users` to add more users and optionally grant admin status.
- The header shows an “Admin” link only for admins.

## Troubleshooting

- Tor not ready yet: watch logs until “Bootstrapped 100%”.

```bash
docker compose logs -f tor
```

- Need the onion name again:

```bash
docker compose exec tor sh -lc 'cat /var/lib/tor/hidden_service/hostname'
```

- Port in use: change the host port mapping in `docker-compose.yml` (e.g., `8090:8080`).

## License

See `LICENSE` in this repository.
