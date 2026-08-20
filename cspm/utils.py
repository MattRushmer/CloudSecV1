def parse_resource_group(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1]
