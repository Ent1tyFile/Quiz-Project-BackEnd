"""description

Revision ID: 4226463d0cf8
Revises: 
Create Date: 2023-05-27 22:11:43.682691

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4226463d0cf8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('quiz',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('quiz_identifier', sa.String(length=6), nullable=False),
    sa.Column('quiz_name', sa.String(length=100), nullable=False),
    sa.Column('contents', sa.String(), nullable=False),
    sa.Column('published', sa.Boolean(), nullable=True),
    sa.Column('creator', sa.String(length=100), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_table('quiz')
    # ### end Alembic commands ###
