import os
import random
import string
import hashlib
import hmac
import re
import logging
import jinja2
import webapp2
import time
import urllib
from google.appengine.ext import ndb

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

class UserAccount(ndb.Model):
    username = ndb.StringProperty(required = True)
    pw_hash_s = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, user_id):
        #from 8.4
        return UserAccount.get_by_id(user_id)

    @classmethod
    def get_by_username(cls, username):
        #from 8.4
        u = UserAccount.query().filter(UserAccount.username == username).get()
        return u

    @classmethod
    def register(cls, username, password, email = None):
        #from 8.4
        pw_hash_s = make_pw_hash_s(username, password)
        return UserAccount(username=username, pw_hash_s=pw_hash_s, email=email)

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.StringProperty(required = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    num_comments = ndb.IntegerProperty(required = True, default = 0)
    upvotes = ndb.IntegerProperty(required = True, default = 0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>') #l6.2
        return self.render_str('blog_item.html', post = self)

    def my_render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str('my_blog_item.html', post = self)

    def render_str(self, template, **params):#from HW solutions
        t = jinja_env.get_template(template)
        return t.render(params)

class Comment(ndb.Model):
    author = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str('comment_item.html', comment = self)

    def render_str(self, template, **params):
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

    def render_blog(self, msg=None):
        posts = posts = Post.query().order(-Post.created).fetch(10)
        self.render("blog_main_page.html", posts=posts, msg=msg)

    def get_from_url(self, url_string):
        key = ndb.Key(urlsafe=url_string)
        entity = key.get()
        return entity

class CookieEnabled(Handler):
    def login(self, user):
        self.make_cookie(user)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_creds=; Path=/')
        self.redirect('/blog')

    def make_cookie(self, user):
        user_creds = self.make_val_hash(str(user.key.id()))
        self.response.headers.add_header('Set-Cookie', 'user_creds=%s Path=/' % (user_creds))

    def verify_cookie(self):
        val_hash = self.request.cookies.get('user_creds')
        if not (val_hash and self.verify_val_hash(val_hash)):
            return False
        else:
            return val_hash.split('|')[0]

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
        username = username.lower()
        users = UserAccount.query()
        for user in users:
            if user.username.lower() == username:
                return False
        return True

class LoginRequired(CookieEnabled):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.verify_cookie()
        if not user_id:
            self.redirect('/blog/login?u_error=login')
        else:
            self.user = UserAccount.by_id(int(user_id))
            logging.info("initialize: " + self.user.username)

class RedirectToBlog(Handler):
    def get(self):
        self.redirect('/blog')

class BlogMainPage(Handler):
    def get(self):
        self.render_blog()

class PostsBy(Handler):
    def get(self):
        author = self.request.get('p')
        posts = Post.query(Post.author == author).order(-Post.created).fetch(20)
        if len(posts) == 0:
            self.render('blog_main_page.html', posts=posts, msg='No posts found for %s' % author)
        else:
            self.render('posts_by.html', posts=posts, author=author)

class MyPosts(LoginRequired):
    def get(self):
        posts = Post.query(Post.author == self.user.username).order(-Post.created).fetch(20)
        self.render('my_posts.html', posts=posts, username = self.user.username)

class EditPost(LoginRequired):
    def get(self, url_string):
        post = self.get_from_url(url_string)
        if not post:
            self.error(404)
            return
        else:
            self.render('edit_post.html', subject=post.subject, content=post.content)

    def post(self, url_string):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post = self.get_from_url(url_string)
            post.subject = subject
            post.content = content
            post.put()
            time.sleep(1)
            self.render_blog(msg='Successful edit to "%s"' % post.subject)
        elif not subject:
            self.render('edit_post.html', subject=subject, title=title, error='Post has no title')
        else:
            self.render('edit_post.html', subject=subject, title=title, error = 'Post has no content')

class DeletePost(LoginRequired):
    def get(self, url_string):
        post = self.get_from_url(url_string)
        if not post:
            self.error(404)
            return
        elif not post.author == self.user.username:
                self.redirect('/blog/myposts')
        else:
            self.render('delete_post.html', post=post)

    def post(self, url_string):
        post = self.get_from_url(url_string)
        post.key.delete()
        time.sleep(.5)
        self.redirect('/blog/myposts')



class PermLink(Handler):
    def render_item(self, url_string):
        post = self.get_from_url(url_string)
        logging.info(post)
        if post:
            self.render("permanent_link.html", post=post)
        else:
            self.error(404)
            return

    def get(self, post_id):
        self.render_item(post_id)

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
        elif not(verify and password and username and not (email is False)):
            self.render('signup.html', username=username, password=password, verify=verify, email=email, u_error='')
        else:
            u = UserAccount.register(username, password, email)
            u.put()
            logging.info(username + password)
            self.login(u)
            self.redirect('/blog/welcome')

class Login(CookieEnabled):
    def get(self):
        if self.request.get('u_error'):
            self.render('login.html', u_error='Must be logged in to post')
        else:
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
        posts = Post.query().order(-Post.created).fetch(10)
        self.render('blog_main_page.html', posts=posts, msg='Welcome, %s!' % self.user.username)

class NewPost(LoginRequired):
    def get(self):
        self.render('new_post.html', subject="", content="", error="")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(subject=subject, content=content, author=self.user.username)
            p.put()
            time.sleep(1)
            self.render_blog(msg='Successful post to NateBlog')
            #self.redirect("/blog/" + str(p.key().id()))
        else:
            error = "Must enter title and text"
            self.render('new_post.html', subject=subject, content=content, error=error)

class CommentPage(Handler):
    def get(self, url_string):
        post = self.get_from_url(url_string)
        if not post:
            self.error(404)
            return
        else:
            comments = Comment.query(ancestor=post.key).order(-Comment.created).fetch()#fetch all
            if len(comments) == 0:
                comments = None
            self.render('view_comments.html', post=post, comments=comments)


class PostComment(LoginRequired):
    def get(self, url_string):
        post = self.get_from_url(url_string)
        if not post:
            self.error(404)
            return
        else:
            if self.request.get('error') == 1:
                error = 'Comment is empty'
            else:
                error = None
            self.render('post_comment.html', post=post, error=error)

    def post(self, url_string):
        post = self.get_from_url(url_string)
        content = self.request.get('content')
        if not content:
            self.redirect('/blog/postcomment/%s?error=1' % urlsafe(post.key))
        c = Comment(author=self.user.username, content=content, parent=post.key)
        c.put()
        post.num_comments += 1
        time.sleep(1)
        self.render_blog(msg='Comment Added')

app = webapp2.WSGIApplication([('/', RedirectToBlog),
                                ('/blog', BlogMainPage),
                                ('/blog/signup', Signup),
                                ('/blog/login', Login),
                                ('/blog/welcome', WelcomePage),
                                ('/blog/newpost', NewPost),
                                ('/blog/postsby', PostsBy),
                                ('/blog/myposts', MyPosts),
                                ('/blog/edit/([0-9a-zA-Z-]+)', EditPost),
                                ('/blog/delete/([0-9a-zA-Z-]+)', DeletePost),
                                ('/blog/([0-9a-zA-Z-]+)', PermLink),
                                ('/blog/comments/([0-9a-zA-Z-]+)', CommentPage),
                                ('/blog/postcomment/([0-9a-zA-Z-]+)', PostComment)], debug=True)
