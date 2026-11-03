# biochef-coordinator

The BioChef Coordination Hub. It stores studies, each node's approvals and jobs, which agents fetch by polling. It relays signed and encrypted documents, and reads no job payload or result.

The API is described in [openapi.json](openapi.json). Once the service is running, it is browsable at http://localhost:8000/docs.

## Run it

You need Docker. Copy the example settings, then start Postgres and the service:

```sh
cp example.env .env
docker compose up --build
```

The service answers on http://localhost:8000, and `GET /healthz` reports whether it can reach its database.

## Develop

You need [uv](https://docs.astral.sh/uv/) and Docker. uv installs Python 3.12 and the dependencies:

```sh
cp example.env .env
uv sync
docker compose up -d db                           # Postgres only
uv run uvicorn coordinator.main:app --reload      # http://localhost:8000
```

| Task | Command |
|---|---|
| Lint and format | `uv run ruff check --fix && uv run ruff format` |
| Regenerate `openapi.json` after changing the API | `uv run python -m coordinator.openapi` |

Settings are environment variables starting with `COORDINATOR_`, or lines in `.env`; [example.env](example.env) lists them. Never commit `.env`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
