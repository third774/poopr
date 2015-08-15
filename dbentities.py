from google.appengine.ext import db
from hashfuncs import *

class User(db.Model):
    username = db.StringProperty(required = True)
    lower_username = db.StringProperty()
    salty_password = db.StringProperty(required = True)
    email = db.EmailProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(
            name = name,
            pw_hash = pw_hash,
            email = email)

    @classmethod
    def login(clas, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()
    source_ip = db.StringProperty()

class Insult(db.Model):
    insult = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    approved = db.BooleanProperty(required=True, default=False)
    reviewed = db.BooleanProperty(required=True, default=False)    
    source_ip = db.StringProperty()

class Blog_Post(db.Model):
    title = db.StringProperty(required = True)
    post = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    username = db.StringProperty(required = True)
    user_id = db.StringProperty(required = True)

    def render_post(self):
        self._render_text = self.post.replace('\n', '<br>')
        return self._render_text

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.title,
            'content': self.post,
            'created': self.created.strftime(time_fmt)
            }
        return d