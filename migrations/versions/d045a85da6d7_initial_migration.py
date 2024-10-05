"""Initial migration

Revision ID: d045a85da6d7
Revises: 
Create Date: 2024-09-22 14:09:39.103810

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd045a85da6d7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=150), nullable=False),
    sa.Column('password', sa.String(length=150), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=True),
    sa.Column('totp_secret', sa.String(length=16), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('file',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=200), nullable=False),
    sa.Column('encrypted_path', sa.String(length=200), nullable=False),
    sa.Column('encryption_key', sa.String(length=64), nullable=False),
    sa.Column('checksum', sa.String(length=64), nullable=False),
    sa.Column('owner_id', sa.Integer(), nullable=False),
    sa.Column('uploaded_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('backup',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('file_id', sa.Integer(), nullable=True),
    sa.Column('backup_path', sa.String(length=200), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['file_id'], ['file.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('file_access',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('file_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('permission', sa.String(length=10), nullable=True),
    sa.ForeignKeyConstraint(['file_id'], ['file.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('recovery_request',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('file_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.ForeignKeyConstraint(['file_id'], ['file.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('recovery_request')
    op.drop_table('file_access')
    op.drop_table('backup')
    op.drop_table('file')
    op.drop_table('user')
    # ### end Alembic commands ###
