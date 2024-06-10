"""Add currency code to product model

Revision ID: adc32def90c5
Revises: 2d5e857896a4
Create Date: 2024-06-10 10:39:45.773792

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'adc32def90c5'
down_revision: Union[str, None] = '2d5e857896a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.add_column(sa.Column('currency_code', sa.String(length=3), nullable=False, server_default='USD'))

    # Set default currency_code for existing products
    op.execute('UPDATE products SET currency_code = \'USD\' WHERE currency_code IS NULL')

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.drop_column('currency_code')

    # ### end Alembic commands ###