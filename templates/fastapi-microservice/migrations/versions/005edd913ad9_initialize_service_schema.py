"""initialize service schema

Revision ID: 005edd913ad9
Revises:
Create Date: 2026-10-24 12:07:53.511938

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "005edd913ad9"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""


def downgrade() -> None:
    """Downgrade schema."""
