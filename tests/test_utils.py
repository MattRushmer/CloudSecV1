import pytest

from cspm.utils import parse_resource_group


def test_parses_resource_group_from_a_well_formed_id():
    resource_id = "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql1"
    assert parse_resource_group(resource_id) == "rg1"


def test_raises_clear_error_for_id_missing_resource_group_segment():
    with pytest.raises(ValueError, match="Could not parse resource group"):
        parse_resource_group("/subscriptions/x/providers/Microsoft.Sql/servers/sql1")
