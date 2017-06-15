# NateBlog
Site with multi-user blog functionality for the 'Web Applications and Development' module of the Udacity Full-Stack Web Developer Nanodegree Program

## Usage
    The blog can be accessed without a user account; however, users must log in to create, edit, comment or upvote posts. Logged in users are provided with additional navigation bar links as well as links to edit only their posts and comments. Users must choose a unique username (case insensitive) consisting of letters, numbers, underscores or dashes. Usernames, like passwords, must be at least 3 characters and no more than 20.

## Features

### Main Page
    The main page displays the 10 most recent posts on the blog. Revisions to the post do not affect this ordering.  The grey header serves as a link to this page as does the 'Recent' tab in the navigation bar. An 'Edit' option is provided to posts that have been authored by the logged in user. Users are given a link to view comments only if there are comments to be viewed.

### Most Popular
    This page displays the 10 most upvoted posts on the blog. In all other regards it is like the Main Page.

### PostsBy
    Below the title of a post is the author's name, which, if clicked, links to the 10 most recent posts by that author. If the user is logged in and she clicks on her own name, she is directed to the MyPosts page.

### MyPosts
    Similar to PostsBy, MyPosts displays the user's posts. It is accessed by clicking on the 'MyPosts' tab in the navigation bar or, as mentioned, by clicking on the user's name below one of her posts' titles.

### Upvote
    Clicking the 'up-arrow' symbol below a post links to a single post with comments displayed. Users must be logged in to access this function. Additionally, users are not permitted to upvote their own posts or upvote a single post twice. Clicking upvote on an already upvoted post will lead to the upvote being rescinded.

### Messages
    Messages are displayed in the header to indicate that actions have been performed successfully or to provide an indication that or explanation for an action not being carried out.

## Technical
    This blog runs on the Google App Engine platform, uses the webapp2 framework, and uses the NDB datastore engine. It employs Python for the server code and uses Jinja2 as its templating language.
