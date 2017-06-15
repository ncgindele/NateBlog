import os
import random
import string
import hashlib
import hmac
import re
import time

import jinja2
import webapp2
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

NOT_FOUND_URL = '/blog/pagenotfound'
SHH_SECRET = 'foTz-6yr$1L.7~0FHcEW!b?6g2*CsJ'
    # This string is used to make a secure password hash. Should not be public

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


#ndb Entities
class MyEntity(ndb.Model):
    def put_delay(self, delay=1):
        # Initiates change to entity then waits to allow database to update
        self.put()
        time.sleep(1)


class UserAccount(MyEntity):
    """Stores account information for blog users. Usernames are unique to
    UserAccounts and are case-insensitive."""
    username = ndb.StringProperty(required = True)
    pw_hash_s = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
        # Users do not need to provide an email address to create an account.
        # Multiple UserAccounts can be created from the same email address.

    @classmethod
    def get_by_username(cls, username):
        # from Udacity lesson 8.4
        u = cls.query().filter(cls.username == username).get()
        return u

    @classmethod
    def register(cls, username, password, email = None):
        # from Udacity lesson 8.4
        pw_hash_s = make_pw_hash_s(username, password)
        return cls(username=username, pw_hash_s=pw_hash_s, email=email)


class Post(MyEntity):
    """A Post stores data for a single blog entry. Posts can only be edited
    or deleted by their own author.
    """
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.StringProperty(required = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    num_comments = ndb.IntegerProperty(required = True, default = 0)
    num_upvotes = ndb.IntegerProperty(required = True, default = 0)

    def render(self, **params):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str('blog_item.html', post = self, **params)

    def my_render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str('my_blog_item.html', post = self)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


class Comment(MyEntity):
    """A Comment stores data for a single comment on a single post. When
    initialized, Comments should be assigned a parent equal to their respective
    post's key. Comments can only be edited or deleted by their own author.
    """
    author = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def render(self, username=None):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str('comment_item.html', comment=self, username=username)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


class UpVote(MyEntity):
    """An Upvote is a relation between a Post and a user's UserAccount. User's
    are not permitted to upvote their own posts or upvote the same post twice
    (results in a withdrawl of the upvote).
    """
    post_id = ndb.IntegerProperty(required = True)
    user_id = ndb.IntegerProperty()


# Handlers
class Handler(webapp2.RequestHandler):
    # General methods
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_from_url(self, url_string):
        try:
            key = ndb.Key(urlsafe=url_string)
            entity = key.get()
            return entity
        except:                  # When url does not provide a valid key
            return False

    def ensure_obj(self, obj, address=NOT_FOUND_URL):
        # redirects to 'address' if 'obj' is NoneType
        if not obj:
            self.redirect(address, permanent=True, abort=True)
        else:
            return obj


    # Blog-specific methods
    def render_blog(self, popular=False, username=None, logged_in=False, msg=None, view_comments=False, post_comment=False):
        posts = Post.query().order(-Post.created).fetch(10)
        self.render("blog_main_page.html", posts=posts, username=username, logged_in=logged_in, msg=msg)

    def render_blog_popular(self, popular=False, username=None, logged_in=False, msg=None, view_comments=False, post_comment=False):
        posts = Post.query().order(-Post.num_upvotes).fetch(5)
        self.render("blog_main_page_popular.html", posts=posts, username=username, logged_in=logged_in)

class PageNotFound(Handler):
    def get(self):
        self.error(404)
        self.response.out.write('Error 404: The page you requested was not found')

class CookieEnabled(Handler):
    """Provides Handler with login-related methods, user-information"""
    def startup(self):
        user_id = self.verify_cookie()
        if user_id:
            logged_in = True
            user = UserAccount.get_by_id(int(user_id))
        else:
            logged_in = False
            user = None
        return (user, logged_in)

    def get_username(self, user):
        if isinstance(user, UserAccount):
            return user.username
        else:
            return ''

    def login(self, user):
        self.make_cookie(user)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_creds=; Path=/')
        self.redirect('/blog/signup', permanent=True)

    def make_cookie(self, user):
        user_creds = self.make_val_hash(str(user.key.id()))
        self.response.headers.add_header('Set-Cookie', 'user_creds=%s; Path=/' % (user_creds))

    def verify_cookie(self):
        val_hash = self.request.cookies.get('user_creds')
        if not (val_hash and self.verify_val_hash(val_hash)): # invalid cookie
            self.response.headers.add_header('Set-Cookie', 'user_creds=; Path=/')
            return False
        else:
            return val_hash.split('|')[0] # hash of UserAccount id

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
    def startup(self):
        user_id = self.verify_cookie()
        if user_id:
            return UserAccount.get_by_id(int(user_id))
        else:
            return None


# Single Post Handlers
class PermLink(CookieEnabled):
    def get(self, url_string):
        post = self.ensure_obj(self.get_from_url(url_string))
        msg = self.get_msg()
        user, logged_in = self.startup()
        username = self.get_username(user)
        self.render('perm_link.html', post=post, username=username, msg=msg, logged_in=logged_in)

    def get_msg(self):
        msg = self.request.get('msg')
        if msg == '1':
            return 'Successful post to NateBlog'
        elif msg == '2':
            return 'Sucessful edit to post'
        else:
            return ''

class CommentPage(CookieEnabled):
    # Displays post with comments
    def get(self, url_string):
        up_bool = self.request.get('p') # True if user wants to upvote
        val = self.startup()
        user, logged_in = val[0], val[1]
        post = self.ensure_obj(self.get_from_url(url_string))
        msg = self.get_msg(logged_in, user, post)
        username = self.get_username(user)
        comments = Comment.query(ancestor=post.key).order(Comment.created).fetch(100)
        self.render('view_comments.html', post=post, comments=comments, username=username, msg=msg, logged_in=logged_in)

    def get_msg(self, logged_in, user, post):
        MSG_DICT = {'1': 'Comment posted to NateBlog',
                    '2': 'Comment successfually edited',
                    '3': 'Error: You must be logged in to upvote',
                    '4': 'Error: You cannot upvote your own post',
                    '5': 'You have rescinded your upvote',
                    '6': 'You upvoted this post'}
        if self.request.get('upvote'):
            msg = self.process_upvote(user, post)
        else:
            msg = self.request.get('msg')
        if msg:
            return MSG_DICT[msg]
        else:
            return ''

    def process_upvote(self, user, post):
        if not user:
            return '3'
        if user.username == post.author:
            return '4'
        prev_upvote = UpVote.query(UpVote.user_id == user.key.id(),
                                   UpVote.post_id == post.key.id()).get()
        if prev_upvote:
            self.downvote_post(user, post, prev_upvote)
        else:
            self.upvote_post(user, post)

    def downvote_post(self, user, post, prev_upvote):
        target_url = '/blog/comments/%s?msg=5' % post.key.urlsafe()
        # URL target for redirect, prevents upvote change due to user refresh
        prev_upvote.user_id = None
        prev_upvote.key.delete()
        prev_upvote.put()
        post.num_upvotes -= 1
        post.put_delay()
        self.redirect(target_url, permanent=True, abort=True)

    def upvote_post(self, user, post):
        target_url = '/blog/comments/%s?msg=6' % post.key.urlsafe()
        upvote = UpVote(user_id=user.key.id(), post_id=post.key.id())
        upvote.put()
        post.num_upvotes += 1
        post.put_delay()
        self.redirect(target_url, permanent=True, abort=True)


#Multi-post Handlers
class RedirectToBlog(Handler):
    def get(self):
        self.redirect('/blog', permanent=True)

class BlogMainPage(CookieEnabled):
    # Renders 10 most recent posts
    def get(self):
        user, logged_in = self.startup()
        username = self.get_username(user)
        self.render_blog(logged_in=logged_in, username=username)

class Popular(CookieEnabled):
    # Renders 10 most upvoted posts
    def get(self):
        user, logged_in = self.startup()
        username = self.get_username(user)
        self.render_blog_popular(logged_in=logged_in, username=username)

class PostsBy(CookieEnabled):
    def get(self):
        user = self.startup()[0]
        username = self.get_username(user)
        author = self.request.get('p')
        if user.username == author:
            self.redirect('/blog/myposts', permanent=True, abort=True)
        posts = Post.query(Post.author == author).order(-Post.created).fetch(10)
        if len(posts) == 0:
            self.render('blog_main_page.html', posts=posts,
                        msg='No posts found for %s' % author)
        else:
            self.render('posts_by.html', posts=posts, author=author)

class MyPosts(LoginRequired):
    def get(self):
        user = self.ensure_obj(self.startup(),
                               '/blog/login?action=view+MyPosts')
        q = Post.query(Post.author == user.username)
        posts = q.order(-Post.created).fetch(10)
        self.render('my_posts.html', posts=posts, username=user.username)


#Login Related Handlers
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
            # Username error
            self.render('signup.html', username='', password=password,
                        verify=verify, email=email, u_error=username[1])
        elif not(verify and password and username and not (email is False)):
            # Other error (e.g. password is invalid, does not match other entry
            self.render('signup.html', username=username, password=password,
                        verify=verify, email=email, u_error='')
        else:
            # Successful signup
            u = UserAccount.register(username, password, email)
            u.put_delay()
            self.login(u)
            self.redirect('/blog/welcome', permanent=True)

class Login(CookieEnabled):
    def get(self):
        action = self.request.get('action')
        if action:
            self.render('login.html', msg='Must be logged in to %s' % action)
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
            self.render('login.html', username='', password='',
                        p_error='Invalid Login')

    def authenticate_credentials(self, username, password):
        user = UserAccount.get_by_username(username)
        if not user:
            return False
        else:
            salt = user.pw_hash_s.split('|')[1]
            pw_hash_s = make_pw_hash_s(username=username, password=password, salt=salt)
            if pw_hash_s == user.pw_hash_s:
                return user
            else:
                return False

class Logout(CookieEnabled):
    # Deletes 'user_creds' cookie
    def get(self):
        self.logout()

class WelcomePage(LoginRequired):
    def get(self):
        user = self.ensure_obj(self.startup(), '/blog/signup')
        posts = Post.query().order(-Post.created).fetch(10)
        self.render_blog('blog_main_page.html', logged_in=True,
                         msg='Welcome, %s!' % user.username)


#Handlers for Creating, Editing, Deleting Entities
class NewPost(LoginRequired):
    #Create a new Post on the blog
    def get(self):
        user = self.ensure_obj(self.startup(), '/blog/login?action=post')
        self.render('new_post.html', subject="", content="", error="",
                    msg='Logged in as %s' % user.username)

    def post(self):
        user = self.ensure_obj(self.startup(), '/blog/login?action=post')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            p = Post(subject=subject, content=content, author=user.username)
            p.put_delay()
            self.redirect('/blog/post/%s?msg=1' % p.key.urlsafe(),
                          permanent=True)
        else:
            error = "Must enter title and text"
            self.render('new_post.html', subject=subject, content=content,
                        error=error)

class EditPost(LoginRequired):
    def get(self, url_string):
        user = self.startup()
        msg = 'Logged in as %s' % user.username
        post = self.ensure_obj(self.get_from_url(url_string))
        self.render('edit_post.html', post=post, msg=msg)

    def post(self, url_string):
        post = self.get_from_url(url_string)
        post.subject = self.request.get('subject')
        post.content = self.request.get('content')
        if post.subject and post.content:
            post.put_delay()
            self.redirect('/blog/post/%s?msg=2' % post.key.urlsafe())
        elif not subject:
            self.render('edit_post.html', subject=subject, content=content,
                        error='Post has no title')
        else:
            self.render('edit_post.html', subject=subject, content=content,
                        error='Post has no content')

class PostComment(LoginRequired):
    def get(self, url_string):
        user = self.ensure_obj(self.startup(), '/blog/login?action=comment')
        post = self.ensure_obj(self.get_from_url(url_string))
        if self.request.get('error') == 1:
            error = 'Comment is empty'
        else:
            error = None
        self.render('post_comment.html', post=post, post_comment=True,
                    error=error)

    def post(self, url_string):
        user = self.startup()
        post = self.get_from_url(url_string)
        redirect_target = '/blog/postcomment/%s?error=1' % post.key.urlsafe()
        content = self.ensure_obj(self.request.get('content'), redirect_target)
        c = Comment(author=user.username, content=content, parent=post.key)
        c.put()
        post.num_comments += 1
        post.put_delay()
        self.redirect('/blog/comments/%s?msg=1#comment' % post.key.urlsafe())

class EditComment(LoginRequired):
    def get(self, url_string):
        user = self.startup()
        msg = 'Logged in as %s' % user.username
        comment = self.ensure_obj(self.get_from_url(url_string))
        post = self.ensure_obj(comment.key.parent().get())
        self.render('edit_comment.html', comment=comment, post=post)

    def post(self, url_string):
        content = self.request.get('content')
        comment = self.get_from_url(url_string)
        if content:
            comment.content = content
            comment.put_delay()
            target = '/blog/comments/%s?msg=2#comment'
            self.redirect(target % comment.key.parent().urlsafe())
        else:
            self.render('edit_comment.html', content=comment.content,
                        error="No content to comment",
                        url_id=comment.key.urlsafe())

class DeleteItem(LoginRequired):
    def get(self, url_string):
        user = self.ensure_obj(self.startup(), '/blog/login?action=delete')
        item = self.ensure_obj(self.get_from_url(url_string))
        if not item.author == user.username:
                self.redirect('/blog', permanent=True)
        else:
            if isinstance(item, Post):
                self.render('delete_item.html', name=item.subject)
            else: # item is a Comment
                self.render('delete_item.html', name='comment')

    def post(self, url_string):
        item = self.ensure_obj(self.get_from_url(url_string))
        if isinstance(item, Comment):
            post = item.key.parent().get()
            post.num_comments = post.num_comments - 1
            post.put()
        else: #item is a Post
            comments = Comment.query(ancestor=item.key).fetch()
            for comment in comments:
                comment.key.delete()
        item.key.delete()
        time.sleep(1)
        self.redirect('/blog/myposts')


app = webapp2.WSGIApplication([('/', RedirectToBlog),
                                ('/blog', BlogMainPage),
                                ('/blog/popular', Popular),
                                ('/blog/signup', Signup),
                                ('/blog/login', Login),
                                ('/blog/logout', Logout),
                                ('/blog/welcome', WelcomePage),
                                ('/blog/newpost', NewPost),
                                ('/blog/postsby', PostsBy),
                                ('/blog/myposts', MyPosts),
                                ('/blog/post/([0-9a-zA-Z-]+)', PermLink),
                                ('/blog/edit/([0-9a-zA-Z-]+)', EditPost),
                                ('/blog/editcomment/([0-9a-zA-Z-]+)', EditComment),
                                ('/blog/delete/([0-9a-zA-Z-]+)', DeleteItem),
                                ('/blog/comments/([0-9a-zA-Z-]+)', CommentPage),
                                ('/blog/postcomment/([0-9a-zA-Z-]+)', PostComment),
                                ('/blog/pagenotfound', PageNotFound)], debug=True)
