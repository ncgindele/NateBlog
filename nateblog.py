import os
import random
import string
import hashlib
import hmac
import re
import logging
import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SHH_SECRET = 'foTz-6yr$1L.7~0FHcEW!b?6g2*CsJ'


def make_salt():
    rand = ''
    for x in range(5):
        rand += random.choice(string.letters)
    return rand

def make_pw_hash_s(username, password, salt=0):
    if salt == 0:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (h, salt)

def users_key(group='default'):
    #from HW solutions
    return db.Key.from_path('users', group)

class UserAccount(db.Model):
    username = db.StringProperty(required = True)
    pw_hash_s = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, user_id):
        #from 8.4
        return UserAccount.get_by_id(user_id, parent = users_key())

    @classmethod
    def get_by_username(cls, username):
        #from 8.4
        u = UserAccount.all().filter('username =', username).get()
        return u

    @classmethod
    def register(cls, username, password, email = None):
        #from 8.4
        pw_hash_s = make_pw_hash_s(username, password)
        return UserAccount(parent = users_key(), username=username, pw_hash_s=pw_hash_s, email=email)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>') #l6.2
        return self.render_str("blog_item.html", post = self)

    def render_str(self, template, **params):#from HW solutions
        t = jinja_env.get_template(template)
        return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        #params['user'] = self.user delete
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class CookieEnabled(Handler):
    def login(self, user):
        self.make_cookie(user)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_creds=; Path=/')
        self.redirect('/blog')

    def make_cookie(self, user):
        user_creds = self.make_val_hash(str(user.key().id()))
        self.response.headers.add_header('Set-Cookie', 'user_creds=%s Path=/' % (user_creds))

    def verify_cookie(self):
        val_hash = self.request.cookies.get('user_creds')
        if self.verify_val_hash(val_hash):
            return val_hash.split('|')[0]
        else:
            return False

    def make_val_hash(self, value):
        val_hash = '%s|%s' % (value, hmac.new(SHH_SECRET, value).hexdigest())
        return val_hash

    def verify_val_hash(self, val_hash):
        value = val_hash.split('|')[0]
        return self.make_val_hash(value) == val_hash


    def verify_password(self, password):
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        if PASSWORD_RE.match(password):
            return password
        else:
            return False

    def verify_match(self, password, verify):
        if password == verify:
            return password
        else:
            return False

    def verify_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if EMAIL_RE.match(email):
            return email
        else:
            return None

    def verify_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            if self.name_not_taken(username):
                return username
            else:
                return ('', 'Error: username already taken')
        else:
            return ('', 'Error: invalid username')

    def name_not_taken(self, username):
            user = UserAccount.get_by_username(username)
            if user:
                return False
            else:
                return True

class LoginRequired(CookieEnabled):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.verify_cookie()
        if not user_id:
            self.redirect('/login')
        else:
            self.user = UserAccount.by_id(int(user_id))
            logging.info('Got user' + self.user.username)

class BlogMainPage(Handler):
    def render_blog(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10") #retrieve 10 most recent
        self.render("blog_main_page.html", posts=posts)

    def get(self):
        self.render_blog()

class PostsBy(Handler): pass

class Signup(CookieEnabled):
    def get(self):
        self.render('signup.html')

    def post(self):
        password = self.request.get('password')
        verify = self.verify_match(password, self.request.get('verify'))
        password = self.verify_password(password)
        username = self.verify_username(self.request.get('username'))
        email = self.verify_email(self.request.get('email'))
        if type(username) is tuple:
            self.render('signup.html', username='', password=password, verify=verify, email=email, u_error=username[1])
        elif type(password) is tuple:
            self.render('signup.html', username=username, password='', verify=verify, p_error=password[1])
        elif not(verify and password and username and not (email is False)):
            self.render('signup.html', username=username, password=password, verify=verify, email=email)
        else:
            u = UserAccount.register(username, password, email)
            u.put()
            logging.info(username + password)
            self.login(u)
            self.redirect('/blog/welcome')

class Login(CookieEnabled):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = self.authenticate_credentials(username, password)
        if user:
            self.login(user)
            self.redirect('/blog/welcome')
        else:
            self.render('login.html', username='', password='', p_error='Invalid Login')

    def authenticate_credentials(self, username, password):
        user = UserAccount.get_by_username(username)
        if not user:
            return False
        else:
            salt = user.pw_hash_s.split('|')[1]
            if make_pw_hash_s(username=username, password=password, salt=salt) == user.pw_hash_s:
                return user
            else:
                return False

class WelcomePage(LoginRequired):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('blog_main_page.html', posts=posts, welcome='Welcome, %s!' % self.user.username)

class NewPost(LoginRequired):
    def get(self):
        self.render('new_post.html', subject="", content="", error="")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(subject=subject, content=content, author=self.user.username)
            p.put() #stores object in db
            self.redirect("/blog/" + str(p.key().id()))
        else:
            error = "Must enter title and text"
            self.render('new_post.html', subject=subject, content=content, error=error)

class PermLink(Handler):
    def render_item(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if post:
            self.render("permanent_link.html", post=post)
        else:
            self.error(404)
            return

    def get(self, post_id):
        self.render_item(post_id)


app = webapp2.WSGIApplication([('/blog', BlogMainPage),
                                ('/blog/signup', Signup),
                                ('/blog/login', Login),
                                ('/blog/welcome', WelcomePage),
                                ('/blog/newpost', NewPost),
                                ('/blog/postsby', PostsBy),
                                ('/blog/(\d+)', PermLink)], debug=True)
