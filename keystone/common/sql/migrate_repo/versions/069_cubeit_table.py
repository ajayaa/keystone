
from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql


LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine


    user = sql.Table(
            'cubeit_user', meta,
            sql.Column('id', sql.Integer(), primary_key=True),
            sql.Column('name', sql.String(255)),
            sql.Column('city', sql.String(255)),
            sql.UniqueConstraint('name', 'city', name='ixu_name_city'),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    cube = sql.Table(
            'cubeit_cube', meta,
            sql.Column('id', sql.Integer(), primary_key=True),
            sql.Column('name', sql.String(255)),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    content = sql.Table(
            'cubeit_content', meta,
            sql.Column('id', sql.Integer(), primary_key=True),
            sql.Column('link', sql.String(1000)),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    user_cube = sql.Table(
            'cubeit_user_cube', meta,
            sql.Column('user_id', sql.Integer(), primary_key=True, autoincrement=False),
            sql.Column('cube_id', sql.Integer(), primary_key=True),
            sql.Column('is_owner', sql.Boolean, default=False),
            sql.ForeignKeyConstraint(
                    ['user_id'], ['cubeit_user.id'],
                    name='fk_user_cube_user_id'
                ),
                sql.ForeignKeyConstraint(
                    ['cube_id'], ['cubeit_cube.id'],
                    name='fk_user_cube_cube_id'
                ),

            mysql_engine='InnoDB',
            mysql_charset='utf8')

    user_content = sql.Table(
            'cubeit_user_content', meta,
            sql.Column('user_id', sql.Integer(), primary_key=True),
            sql.Column('content_id', sql.Integer(), primary_key=True),
            sql.Column('is_owner', sql.Boolean(), default=False),
            sql.ForeignKeyConstraint(
                    ['user_id'], ['cubeit_user.id'],
                    name='fk_user_content_user_id'
                ),
                sql.ForeignKeyConstraint(
                    ['content_id'], ['cubeit_content.id'],
                    name='fk_user_content_cube_id'
                ),

            mysql_engine='InnoDB',
            mysql_charset='utf8')
    cube_content = sql.Table(
            'cubeit_cube_content', meta,
            sql.Column('cube_id', sql.Integer(), primary_key=True),
            sql.Column('content_id', sql.Integer(), primary_key=True),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    # create policy related tables
    tables = [user, cube, content, user_cube, user_content, cube_content]

    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise
