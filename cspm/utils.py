def parse_resource_group(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError(
            f"Could not parse resource group from resource ID: {resource_id!r}"
        ) from exc
