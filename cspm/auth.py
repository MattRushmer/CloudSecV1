import os

from azure.identity import DefaultAzureCredential


def get_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential()


def get_subscription_id() -> str:
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise RuntimeError(
            "AZURE_SUBSCRIPTION_ID is not set. Export it or add it to a .env file "
            "(see env.example)."
        )
    return subscription_id
