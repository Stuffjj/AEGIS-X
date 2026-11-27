
import sqlite3
import uuid
from pathlib import Path


DB_PATH = Path(__file__).resolve().parents[1] / "aegis_x.db"

ORIGINAL_ID = "ef07fce2-9dc8-427a-a86e-02673981cd4d"


def create_tampered_copy():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM evidence_records WHERE evidence_id = ?",
            (ORIGINAL_ID,)
        )

        original = cursor.fetchone()

        if original is None:
            raise ValueError("Original evidence record not found")

        modified = dict(original)

        # Create a separate evidence ID
        modified["evidence_id"] = str(uuid.uuid4())

        # Change the evidence but deliberately preserve its original hash
        modified["action"] = "Unauthorized file access"

        columns = list(modified.keys())

        column_names = ", ".join(columns)
        placeholders = ", ".join(["?"] * len(columns))

        cursor.execute(
            f"INSERT INTO evidence_records ({column_names}) "
            f"VALUES ({placeholders})",
            list(modified.values())
        )

        connection.commit()

        print("Tampered copy created successfully")
        print("Original ID:", ORIGINAL_ID)
        print("Tampered copy ID:", modified["evidence_id"])
        print("Modified action:", modified["action"])
        print("Original hash preserved:", modified["sha256_hash"])

    finally:
        connection.close()


if __name__ == "__main__":
    create_tampered_copy()
