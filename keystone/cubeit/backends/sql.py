# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from keystone.common import sql
from keystone import exception
from keystone import cubeit


class User(sql.ModelBase, sql.DictBase):
    __tablename__ = 'cubeit_user'
    id = sql.Column(sql.Integer(), primary_key=True)
    name = sql.Column(sql.String(255))
    city = sql.Column(sql.String(255))

class Cube(sql.ModelBase, sql.DictBase):
    __tablename__ = 'cubeit_cube'
    id = sql.Column(sql.Integer(), primary_key=True)
    name = sql.Column(sql.String(255), nullable=False)

class Content(sql.ModelBase, sql.DictBase):
    __tablename__ = 'cubeit_content'
    id = sql.Column(sql.Integer, primary_key=True)
    link = sql.Column(sql.String(1000))

class UserCube(sql.ModelBase):
    __tablename__ = 'cubeit_user_cube'
    user_id = sql.Column(sql.Integer, sql.ForeignKey('cubeit_user.id'), primary_key=True)
    cube_id = sql.Column(sql.Integer, sql.ForeignKey('cubeit_cube.id'), primary_key=True)
    is_owner = sql.Column(sql.Boolean)

class UserContent(sql.ModelBase):
    __tablename__ = 'cubeit_user_content'
    user_id = sql.Column(sql.Integer, primary_key=True)
    content_id = sql.Column(sql.Integer, primary_key=True)
    is_owner = sql.Column(sql.Boolean)

class CubeContent(sql.ModelBase):
    __tablename__ = 'cubeit_cube_content'
    cube_id = sql.Column(sql.Integer, sql.ForeignKey('cubeit_cube.id'), primary_key=True)
    content_id = sql.Column(sql.Integer, sql.ForeignKey('cubeit_content.id'), primary_key=True)

class CubeIt(cubeit.Driver):

    @sql.handle_conflicts(conflict_type='cubeit')
    def register_user(self, **kwargs):
        name = kwargs.get('name')
        city = kwargs.get('city')
        with sql.transaction() as session:
            session.add(User(name=name, city=city))
            ref = session.query(User).filter_by(name=name).filter_by(city=city).one()
        return dict(ref)

    @sql.handle_conflicts(conflict_type='cubeit')
    def create_cube(self, user_id, **kwargs):
        name = kwargs.get('name')
        with sql.transaction() as session:
            session.add(Cube(name=name))
            ref = session.query(Cube).filter_by(name=name).one()
            user_id = int(user_id)
            is_owner = True
            session.add(UserCube(user_id=user_id, cube_id=ref.id, is_owner=is_owner))
        ret = dict(ref)
        ret['user_id'] = user_id
        return ret

    def delete_cube(self, user_id, cube_id):
        with sql.transaction() as session:
            session.query(UserCube).filter_by(cube_id=cube_id).delete()
            session.query(Cube).filter_by(id=cube_id).delete()
            session.query(CubeContent).filter_by(cube_id=cube_id).delete()

    def create_content(self, user_id, **kwargs):
        link = kwargs.get('link')
        with sql.transaction() as session:
            session.add(Content(link=link))
            ref = session.query(Content).filter_by(link=link).one()
            user_id = int(user_id)
            is_owner = True
            session.add(UserContent(user_id=user_id, content_id=ref.id, is_owner=is_owner))
        ret = dict(ref)
        ret['user_id'] = user_id
        return ret

    def attach_content_with_cube(self, user_id, cube_id, **kwargs):
        content_id = int(kwargs.get('content_id'))
        with sql.transaction() as session:
            cube_id = int(cube_id)
            session.add(CubeContent(cube_id=cube_id, content_id=content_id))
        ret = {}
        ret['cube_id'] = cube_id
        ret['content_id'] = content_id
        return ret

    def detach_content_from_cube(self, user_id, cube_id, content_id):
        with sql.transaction() as session:
            session.query(CubeContent).filter_by(cube_id=cube_id).filter_by(
                    content_id=content_id).delete()

    def share_content_with_user(self, u_id, content_id, **kwargs):
        user_id = int(kwargs.get('user_id'))
        is_owner = False
        with sql.transaction() as session:
            session.add(UserContent(user_id=int(user_id), content_id=int(content_id), is_owner=is_owner))
        ret = {}
        ret['user_id'] = user_id
        ret['content_id'] = content_id
        return ret

    def share_cube_with_user(self, u_id, cube_id, **kwargs):
        user_id = int(kwargs.get('user_id'))
        is_owner = False
        with sql.transaction() as session:
            session.add(UserCube(user_id=user_id, cube_id=cube_id, is_owner=is_owner))
        ret = {}
        ret['user_id'] = user_id
        ret['cube_id'] = cube_id
        return ret

    def list_cubes_for_user(self, user_id):
        def _model_to_dict(ref):
            ret = dict(ref)
            ret['user_id'] = user_id
            return ret
        user_id = int(user_id)
        ret = []
        with sql.transaction() as session:
            refs = session.query(Cube).join(UserCube, Cube.id==UserCube.cube_id).filter(UserCube.user_id==user_id).all()
            for ref in refs:
                ret.append(_model_to_dict(ref))
        return ret

    def list_contents_for_user(self, user_id):
        def _content_model_to_dict(ref):
            ret = dict(ref)
            ret['user_id'] = user_id
            return ret

        user_id = int(user_id)
        ret = {}
        with sql.transaction() as session:
            refs = session.query(Content).join(UserContent, Content.id==UserContent.content_id).filter(UserContent.user_id==user_id).all()
            for ref in refs:
                ret[ref.id] = _content_model_to_dict(ref)
            refs = session.query(UserCube).filter_by(user_id=user_id).all()
            for ref in refs:
                cube_refs = session.query(CubeContent).filter_by(cube_id=ref.cube_id).all()
                for cube_ref in cube_refs:
                    content_ref = session.query(Content).filter_by(id=cube_ref.content_id).all()
                    ret[ref.id] = _content_model_to_dict(content_ref[0])
        return ret.values()
