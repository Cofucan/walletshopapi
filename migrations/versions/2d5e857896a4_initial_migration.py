"""Initial migration

Revision ID: 2d5e857896a4
Revises: 
Create Date: 2024-05-30 22:19:49.291057

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2d5e857896a4'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('otps',
    sa.Column('id', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('otp', sa.String(length=10), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('otps', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_otps_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_otps_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_otps_otp'), ['otp'], unique=False)

    op.create_table('products',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('price', sa.Float(), nullable=True),
    sa.Column('stock', sa.Integer(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_products_name'), ['name'], unique=False)

    op.create_table('token_blacklist',
    sa.Column('token', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.PrimaryKeyConstraint('token')
    )
    with op.batch_alter_table('token_blacklist', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_token_blacklist_token'), ['token'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('first_name', sa.String(length=64), nullable=True),
    sa.Column('last_name', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('hashed_password', sa.String(length=255), nullable=True),
    sa.Column('is_superadmin', sa.Boolean(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_first_name'), ['first_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_last_name'), ['last_name'], unique=False)

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_last_name'))
        batch_op.drop_index(batch_op.f('ix_users_first_name'))
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    with op.batch_alter_table('token_blacklist', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_token_blacklist_token'))

    op.drop_table('token_blacklist')
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_products_name'))

    op.drop_table('products')
    with op.batch_alter_table('otps', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_otps_otp'))
        batch_op.drop_index(batch_op.f('ix_otps_id'))
        batch_op.drop_index(batch_op.f('ix_otps_email'))

    op.drop_table('otps')
    # ### end Alembic commands ###
