"""Entry point for multi-mode deployment (openenv serve / uv run)."""

import uvicorn


def main(host: str = "0.0.0.0", port: int = 7860) -> None:
    uvicorn.run(
        "incident_triage.server.app:app",
        host=host,
        port=port,
    )


if __name__ == "__main__":
    main()
