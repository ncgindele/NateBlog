import os
import random
import string
import hashlib #remove
import hmac
import re
import logging
import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
class UserAccount(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)

class Post(db.Model):
    def render(self):
        self._render_text = self.content.replace('\n', '<br>') #l6.2
        return render_str("blog_item.html", post = self)

    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_creds=; Path=/')
        self.redirect('/login')

class BlogMainPage(Handler):
    def render_blog(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10") #retrieve 10 most recent
        self.render("blog_main_page.html", posts=posts)
    def get(self):
        self.render_blog()

class PostsBy(Handler): pass

class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        password = self.request.get('password')
        verify = verify_match(password, self.request.get('verify'))
        password = verify_password(password)
        username = verify_username(self.request.get('username'))
        email = verify_email(self.request.get('email'))
        if type(username) is tuple:
            self.render('mytemplate.html', username='', password=password, verify=verify, email=email, u_error=username(1))
        elif type(password) is tuple:
            self.render('mytemplate.html', username=username, password='', verify=verify, p_error=password(1))
        elif not(verify and password and username and not (email is False)):
            self.render('mytemplate.html', username=username, password=password, verify=verify, email=email)
        else:
            pw_hash_s = make_pw_hash_s(username, password)
            pw_hash = pw_hash_s.split('|')[0]
            salt = pw_hash_s.split('|')[1]
            u = UserAccount(username = username, pw_hash = pw_hash, salt = salt)
            u.put()
            self.response.headers.add_header('Set-Cookie', make_Cookie(u, pw_hash))
            self.redirect('/welcome')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        new_cookie = authenticate_credentials(username, password)
        if new_cookie:
            self.response.headers.add_header('Set-Cookie', new_cookie)
            self.redirect('/blog/welcome')
        else:
            self.render('login.html', username='', password='', p_error='Invalid Login')

class WelcomePage(Handler):
    def get(self):
        user_cookie = self.request.cookies.get('user_creds')
        user_id = user_cookie.split('|')[0]
        logging.info(user_id)
        key = db.Key.from_path('UserAccount', int(user_id))
        uacct = db.get(key)
        pw_hash = user_cookie.split('|')[1]
        if uacct.pw_hash == pw_hash:
            self.write('Welcome, %s!' % uacct.username)
        else:
            self.redirect('/logout')

class NewPost(Handler):
    def render_post_new(self, subject="", content="", error=""):
        self.render('post_new.html', subject=subject, content=content, error=error)

    def get(self):
        self.render_post_new()

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put() #stores object in db
            self.redirect("/blog/" + str(p.key().id()))
        else:
            error = "Must enter title and text"
            self.render_post_new(error=error, subject=subject, content=content)

class PermLink(Handler):
    def render_item(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            self.render("permanent_link.html", post=post)
        else:
            self.error(404)
            return

    def get(self, post_id):
        self.render_item(post_id)


def make_Cookie(u, pw_hash=False, pw_hash_s=False):
    user_id = str(u.key().id())
    if not pw_hash:
        pw_hash = pw_hash_s.split('|')[0]
    return str('user_creds=%s|%s; Path=/' % (user_id, pw_hash))

def authenticate_credentials(username, password):
    user = getUser(username)
    if not user:
        return False
    else:
        db_pw_hash_s = get_pw_hash_s(user)
        salt = db_pw_hash_s.split('|')[1]
        if make_pw_hash_s(username=username, password=password, salt=salt) == db_pw_hash_s:
            return make_Cookie(user, pw_hash_s=db_pw_hash_s)
        else:
            return False

def make_salt():
    rand = ''
    for x in range(5):
        rand += random.choice(string.letters)
    return rand

def make_pw_hash_s(username, password, salt=0):
    if salt == 0:
        salt = make_salt()
    h = hashlib.sha256(username + ',' + password + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(username, password, h):
    h_hash = h.split('|')[1]
    hsh = make_pw_hash(username, password, h_hash)
    return hsh == h


def verify_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if USER_RE.match(username):
        if name_not_taken(username):
            logging.info('name is not taken' + username)
            return username
        else:
            logging.info("error username already taken")
            return ('', 'Error: username already taken')
    else:
        return ('', 'Error: invalid username')

def getUser(username):
        u = db.GqlQuery("SELECT * FROM UserAccount WHERE username = :1", username)
        user = u.get()
        if user:
            return user
        else:
            return False

def get_pw_hash_s(user):
        return user.pw_hash + '|' + user.salt

def name_not_taken(username):
    try:
        logging.info("tyring..")
        u = db.GqlQuery("SELECT * FROM UserAccount WHERE username = :1", username)
        if u.get():
            return False
        else:
            return True
    except:
        return True

def verify_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    if PASSWORD_RE.match(password):
        return password
    else:
        return False

def verify_match(password, verify):
    if password == verify:
        return verify
    else:
        return False

def verify_email(email):
    if not email:
        return email
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    if EMAIL_RE.match(email):
        return email
    else:
        return False

app = webapp2.WSGIApplication([('/blog', BlogMainPage),
                                ('/blog/signup', Signup),
                                ('/blog/login', Login),
                                ('/blog/welcome', WelcomePage),
                                ('/blog/newpost', NewPost),
                                ('/blog/postsby', PostsBy),
                                ('/blog/(\d+)', PermLink)], debug=True)
