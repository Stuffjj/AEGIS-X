
from sqlalchemy import inspect, text

from backend.app.core.database import engine, create_tables


def migrate():

    create_tables()

    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns(
            "evidence_provenance"
        )
    }

    migrations = {
        "signature": (
            "ALTER TABLE evidence_provenance "
            "ADD COLUMN signature TEXT"
        ),
        "public_key": (
            "ALTER TABLE evidence_provenance "
            "ADD COLUMN public_key TEXT"
        ),
        "signature_algorithm": (
            "ALTER TABLE evidence_provenance "
            "ADD COLUMN signature_algorithm "
            "VARCHAR(30) NOT NULL DEFAULT 'Ed25519'"
        )
    }

    with engine.begin() as connection:

        for column_name, statement in migrations.items():

            if column_name not in columns:
                connection.execute(text(statement))
                print(f"Added column: {column_name}")

            else:
                print(f"Column already exists: {column_name}")

    print("Provenance signature migration completed.")


if __name__ == "__main__":
    migrate()
