from openenv.core.generic_client import GenericEnvClient


def create_client(base_url: str = "ws://localhost:7860") -> GenericEnvClient:
    return GenericEnvClient(base_url=base_url)
