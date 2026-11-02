"""Downgrade of 30dad796cc32 (mission layers, external data and feeds) on a throwaway SQLite DB."""

import importlib.util
import json
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = next(
    (Path(__file__).parent.parent / "raven" / "migrations" / "versions").glob("30dad796cc32_*.py")
)


def _migration():
    spec = importlib.util.spec_from_file_location("migration_30dad796cc32", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_downgrade_drops_changes_that_need_the_snapshot_columns(tmp_path):
    migration = _migration()
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE missions (name VARCHAR(255) PRIMARY KEY)"))
        connection.execute(
            sa.text(
                "CREATE TABLE mission_changes (id INTEGER PRIMARY KEY, "
                "change_type VARCHAR(255), mission_name VARCHAR(255))"
            )
        )
        operations = Operations(MigrationContext.configure(connection))
        with Operations.context(operations.migration_context):
            migration.upgrade()

        rows = [
            # (id, change_type, external_data, mission_feed, mission_layer)
            (1, "ADD_CONTENT", None, None, None),  # ordinary content change, SQL NULLs
            (2, "ADD_CONTENT", "null", "null", "null"),  # JSON nulls (columns set to None)
            (3, "ADD_CONTENT", json.dumps({"id": "ext-1"}), "null", "null"),
            (4, "REMOVE_CONTENT", json.dumps({"id": "ext-1"}), None, None),
            (5, "CREATE_DATA_FEED", None, json.dumps({"uid": "feed-1"}), None),
            (6, "ADD_MISSION_LAYER", None, None, json.dumps({"uid": "layer-1"})),
        ]
        for row in rows:
            connection.execute(
                sa.text(
                    "INSERT INTO mission_changes (id, change_type, mission_name, external_data, "
                    "mission_feed, mission_layer) VALUES (:id, :type, 'm', :ext, :feed, :layer)"
                ),
                dict(zip(("id", "type", "ext", "feed", "layer"), row)),
            )

        with Operations.context(operations.migration_context):
            migration.downgrade()

        left = connection.execute(sa.text("SELECT id FROM mission_changes ORDER BY id")).scalars()
        assert list(left) == [1, 2]
        columns = {c["name"] for c in sa.inspect(connection).get_columns("mission_changes")}
        assert columns == {"id", "change_type", "mission_name"}
