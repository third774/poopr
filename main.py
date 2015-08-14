import webapp2
import cgi
import re
import jinja2
import os
import hashlib
import random
import hmac
from hashfuncs import *
from dbentities import *
import logging
import time
import urllib2
import urllib
from xml.dom import minidom
from collections import namedtuple
import json
import base64

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

IP_URL = "http://api.hostip.info/?ip="
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&zoom=2&"



def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        y = minidom.parseString(content).getElementsByTagName("gml:coordinates")
        if len(y) > 0: 
            z = y[0].firstChild.nodeValue
            lon, lat = z.split(',')
            return db.GeoPt(lat, lon)

def gmaps_img(points):
    markers = '&'.join('markers=%s,%s' % (p.lat, p.lon)
                        for p in points)
    return GMAPS_URL + markers

def cached_user(uid, update = False):
    if uid != None and uid != "":
        key = uid
        u = memcache.get(key)
        if u is None or update:
            logging.error("DB QUERY ON cached_user")
            u = uid and User.by_id(int(uid))
            if u:
                memcache.set(key, u)
        return u
    else:
        return None

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(User.key().id()))

    def logout(self, user):
        self.respose.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.User = cached_user(uid)

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class welcomeHandler(Handler):
    
    def get(self):
        u = False
        if self.User:
            u = self.User

        self.render("welcome.html", u = u)

class dice(Handler):
    def get(self):
        self.render("dice.html")

    def post(self):
        nodice = self.request.get("nodice")
        nosides = self.request.get("nosides")
        error = ''
        summary = False

        try:
            nodice = int(nodice)
            nosides = int(nosides)
            if nodice == 0 or nosides == 0:
                error = 'Cannot use zeros!'
            else:
                summary = {'rolls' : []}
                for r in range(0, nodice):
                    summary['rolls'].append(random.randint(1, nosides))
                summary['sum'] = sum(summary['rolls'])
                summary['potential'] = nosides * nodice
                summary['percent'] = round(float(sum(summary['rolls'])) / float((nosides * nodice)) * 100, 2)
                
        except ValueError:
            error = 'Please enter integers in both fields!'
        except ZeroDivisionError:
            error = 'Cannot use zeros!'

        self.render("dice.html", error = error, nodice = nodice, nosides = nosides, summary = summary)

def frontpage_posts(update = False):
    key = 'frontpage'
    posts = memcache.get(key)

    if posts is None or update:
        logging.error("DB QUERY")
        results = Blog_Post.all().order('-created')
        posts = {"content": list(results.run(limit=10)),
                "time_created": time.time()}
        memcache.set(key, posts)

    return posts

class blog_main_page(Handler):
    def get(self):
        #posts = db.GqlQuery("select * from Blog_Post order by created desc limit 10")

        posts = frontpage_posts()

        u = False
        if self.User:
            u = self.User

        q_time = int(time.time() - posts['time_created'])
        # self.write("queried " + str(round(time.time() - posts['time_created'], 2)) + " seconds ago")
        if self.format == 'html':
            self.render("blog.html", posts=posts['content'], u = u, q_time = q_time)
        else:
            return self.render_json([p.as_dict() for p in posts['content']])

class blog_json(Handler):
    def get(self):
        results = Blog_Post.all().order('-created')
        posts = results.run(limit=10)
        output = []

        for post in posts:
            output.append({'subject': post.title,
                            'content': post.post,
                            'created_time': post.created.strftime("%b %d, %y - %I:%M %p").replace(' 0', ' ')})
        # output = {'subject': post.title,
        #             'content': post.post,
        #             'created_time': post.created.strftime("%b %d, %y - %I:%M %p").replace(' 0', ' ')}

        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.write(json.dumps(output))

class delete_blog_post(Handler):
    def get(self, postid):
        post = Blog_Post.get_by_id(int(postid))
        if self.User:
            if self.User.username == post.username:
                post.delete()
                time.sleep(.2)
                frontpage_posts(True)

        self.redirect("/blog")    

class user_posts(Handler):
    def get(self, username):
        u = User.by_name(username)
        if u:
            un = u.username
            results = Blog_Post.all().filter('username',un)
            self.render("blog.html", posts=results)
        else:
            self.write("User not found")

def post_cache(post_id, update = False):
    key = post_id
    post = memcache.get(key)

    if post is None or update:
        logging.error("DB QUERY")
        post = {"content": Blog_Post.get_by_id(int(key)),
                "q_time": time.time()}
        memcache.set(key, post)

    return post

class blog_post(Handler):
    def get(self, postid):
                
        cached_post = post_cache(postid)
        post = cached_post["content"]
        q_time = int(time.time() - cached_post["q_time"])
        #post = Blog_Post.get_by_id(int(postid))

        u = False
        if self.User:
            u = self.User

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("blog_post.html", post = post, u = u, q_time = q_time)
        else:
            self.render_json(post.as_dict())

class blog_post_json(Handler):
    def get(self, postid):
        post = Blog_Post.get_by_id(int(postid))
        u = False
        if self.User:
            u = self.User
        output = {'subject': post.title,
                    'content': post.post,
                    'created_time': post.created.strftime("%b %d, %y - %I:%M %p").replace(' 0', ' ')}

        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        self.response.write(json.dumps(output))

class new_blog_post(Handler):
    def get(self):
        if self.User:
            self.render("new_post.html", error="", title="", post="")
        else:
            self.redirect('/signup')

    def post(self):
        title = cgi.escape(self.request.get("subject"))
        post = cgi.escape(self.request.get("content"))

        if title and post:
            p = Blog_Post(title = title, post = post, username = self.User.username, user_id = str(self.User.key().id()))
            p = p.put()
            time.sleep(0.5)
            frontpage_posts(True)
            self.redirect('/blog/' + str(p.id()))
        else:
            error = "Please be sure to enter a Title and a Post!"
            self.render("new_post.html", error = error, title = title, post = post)

def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)

    if arts is None or update:
        logging.error("DB QUERY")
        arts = db.GqlQuery("SELECT * "
                            "FROM Art "
                            "ORDER BY created desc "
                            "LIMIT 10")
            
        #prevent running multiple queries
        arts = list(arts)
        memcache.set(key, arts)

    return arts

class ascii_page(Handler):
    def render_front(self, error="", title="", art="", dbid=""):
        u = False
        if self.User:
            u = self.User

        arts = top_arts()
        #find which arts have coords
        points = []
        points = filter(None, (a.coords for a in arts))

        #generate img url
        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("front.html", u = u, error = error, title = title, art = art, arts = arts, dbid=dbid, img_url = img_url)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        source_ip = self.request.remote_addr

        if title and art:
            a = Art(title = title, art = art, source_ip = source_ip)
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords

            a.put()
            time.sleep(0.5)
            top_arts(True)

            
            self.redirect('/ascii')
        else:
            error = "We need both a title and some artwork!"
            self.render_front(error = error, title = title, art = art)

class memcache_flush(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

class birthday(Handler):
    def get(self):
        self.render("birthday.html")
    
    def post(self):
        def valid_month(self, month):
            months = ['January',
              'February',
              'March',
              'April',
              'May',
              'June',
              'July',
              'August',
              'September',
              'October',
              'November',
              'December']
            month_abbvs = dict((m[:3].lower(), m) for m in months)    
            if month:
                short_month = month[:3].lower()
                return month_abbvs.get(short_month)
                    
        def valid_day(self, day):
            if day and day.isdigit():
                day = int(day)
                if day > 0 and day <= 31:
                    return day
                    
        def valid_year(self, year):
            if year and year.isdigit():
                year = int(year)
                if year >= 1900 and year <= 2020:
                    return year

        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')
        
        month = valid_month(self, user_month)
        day = valid_day(self, user_day)
        year = valid_year(self, user_year)
        
        if not (month and day and year):
            self.render("birthday.html", 
                        error = "That doesn't look like a valid date, friendpal.", 
                        month = cgi.escape(user_month), 
                        day = cgi.escape(user_day), 
                        year = cgi.escape(user_year))
        else:
            self.redirect("/thanks")

class ThanksHandler(Handler):
    def get(self):
        self.render("valid_day.html")

class ShoppingList(Handler):
    def get(self):
        items = self.request.get_all("food")
        self.render("shopping_list.html", items=items)

class FizzBuzzHandler(Handler):
    def get(self):
        n = 0
        self.render('fizzbuzz.html', n=n)

    def post(self):
        n = 0
        n = self.request.get('i', '0')
        error = ""

        if n and n.isdigit() and int(n) != 0:
            n = int(n)
            self.render('fizzbuzz.html', n=n, error=error)
        else:
            error = "Please enter a non-zero number"
            self.render('fizzbuzz.html', n=0, error=error)

class loginHandler(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.all().filter('username', username).get()
        login_valid = False
        if u:
            login_valid = valid_pw(username, password, u.salty_password)

        if login_valid:
            cookie_val = make_secure_val(str(u.key().id()))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_val)
            self.redirect('/welcome')
        else: 
            loginError = 'Invalid username or password'
            self.render('login.html', loginError = loginError)

class logoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/')

class signupHandler(Handler):
    
    def get(self):
        self.render('signup.html')
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        usernameError = ""
        passwordError = ""      
        verifyError = ""
        emailError = ""
        
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        def valid_username(username):
            return USER_RE.match(username)
        
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        def valid_password(password):
            return PASSWORD_RE.match(password)
        
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        def valid_email(email):
            return EMAIL_RE.match(email)

        
        #Check first for duplicate usernames
        #username_lookup = 
            #validate username
        if valid_username(username):
            if User.all().filter('lower_username', username.lower()).get():
                usernameError = "Username is already taken"
                username_is_valid = False
            else:
                username_is_valid = True
        else:
            usernameError = "Invalid Username"
            username_is_valid = False
        
        #validate password
        if valid_password(password) and valid_password(verify):
            if password == verify:
                password_is_valid = True
            else:
                verifyError = "Your passwords didn't match"
                password_is_valid = False
        else:
            password_is_valid = False
            passwordError = "Invalid Password"
            
        
        #validate email
        if email != "":
            if valid_email(email):
                email_is_valid = True
            else:
                emailError = "Invalid Email"
                email_is_valid = False
        else:
            email_is_valid = True

        #execute post and redirect
        if username_is_valid and password_is_valid and email_is_valid:
            #hash password
            hashed_password = make_pw_hash(username, password)
            if email == "":
                email = None
            else:
                email = cgi.escape(email)

            username = cgi.escape(username)

            u = User(username = username, lower_username = username.lower(), salty_password = hashed_password, email = email)
            u.put()

            cookie_val = make_secure_val(str(u.key().id()))

            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_val)
            self.redirect('/welcome')
        else:
            username = cgi.escape(username)
            email = cgi.escape(email)
            self.render('signup.html', 
                        username = username, 
                        email = email, 
                        usernameError = usernameError, 
                        passwordError = passwordError, 
                        verifyError = verifyError, 
                        emailError = emailError)

class poopHandler(Handler):
    def get(self):
        insults = [
            "You're as useless as a Red Lights in Grand Theft Auto",
            "You're as useless as a knitted condom.",
            "You're as useless as a screen door on a submarine.",
            "You're as useless as ejection seats on a helicopter.",
            "You're as useless as Anne Frank's drum kit.",
            "You're as useless as a ham sandwich at a Barmitzvah.",
            "You're as useless as condom machines in the Vatican.",
            "You're as useless as pickup lines to George Clooney",
            "You're as useless as the G in Lasagna.",
            "You're as useless as a glass hammer.",
            "You're as useless as deodorant to cab drivers.",
            "You're as useless as a concrete parachute.",
            "You're as useless as the second shift button on the keyboard.",
            "You're as useless as a wooden frying-pan.",
            "You're as useless as a color blind interior decorator.",
            "You're as useless as the 'ay' in 'okay'",
            "You're as useless as rubber lips on a woodpecker.",
            "You're as useless as a fart in a space suit.",
            "You're as useless as a chocolate fireguard.",
            "You're as useless as a knife without a blade.",
            "You're as useless as a cup of decaf.",
            "You're as useless as a remote without batteries.",
            "You're as useless as a piece of pork at a Jewish wedding.",
            "You're as useless as a phone without a signal.",
            "You're as useless as a keyboard without keys.",
            "You're as useless as a chocolate teapot.",
            "You're as useless as a one-legged man at an arse kicking contest.",
            "You're as useless as handles on a snowball.",
            "You're as useless as a gun without ammo.",
            "You're as useless as a grave robber in a crematorium.",
            "You're as useless as Han Solo without Chewbacca and the Millennium Falcon.",
            "You're as useless as a pen without ink.",
            "You're as useless as an ashtray on a bike.",
            "You're as useless as a Computer without Internet.",
            "You're as useless as an XBox without Llive.",
            "You're as useless as a TV without Cable.",
            "You're as useless as white-out to a computer data entry clerk.",
            "You're as useless as 01100010 01101001 01101110 01100001 01110010 01111001 without 00110000",
            "You're as useless as a underwear to Tarzan."
        ]
        insult = random.choice(insults)
        self.render('poop.html', insult = insult)

class rot13(Handler):
    def ceasar(self, text):
        result = ""

        for let in text:
            if not let.isalpha():
                result += cgi.escape(let)
            else:
                num = ord(let) + 13
                if let.isupper():
                    if num > ord('Z'):
                        num -= 26
                else:
                    if num > ord('z'):
                        num -= 26
                result += chr(num)
        return result

    def get(self):
        self.render('cypher.html')

    def post(self):
        user_text = self.request.get('text')
        cypher_text = self.ceasar(user_text)
    
        self.render('cypher.html', cypher_text = cypher_text)

app = webapp2.WSGIApplication([
    ('/?', poopHandler),
    ('/blog/?(?:\.json)?', blog_main_page),
    ('/flush', memcache_flush),
    #webapp2.Route(r'/.json', handler=blog_json),
    webapp2.Route(r'/birthday', handler=birthday),
    webapp2.Route(r'/thanks', handler=ThanksHandler),
    webapp2.Route(r'/cypher', handler=rot13),
    webapp2.Route(r'/signup', handler=signupHandler),
    webapp2.Route(r'/login', handler=loginHandler),
    webapp2.Route(r'/logout', handler=logoutHandler),
    webapp2.Route(r'/welcome', handler=welcomeHandler),
    webapp2.Route(r'/shoppinglist', handler=ShoppingList),
    webapp2.Route(r'/poop', handler=poopHandler),
    webapp2.Route(r'/fizzbuzz', handler=FizzBuzzHandler), 
    webapp2.Route(r'/ascii', handler=ascii_page), 
    ('/blog/([0-9]+)(?:\.json)?', blog_post),
    #webapp2.Route(r'/<postid:\d+>', handler=blog_post, name='posdtid'),
    #webapp2.Route(r'/<postid:\d+>.json', handler=blog_post_json, name='posdtid'),
    webapp2.Route(r'/blog/delete/<postid:\d+>', handler=delete_blog_post, name='posdtid'),
    webapp2.Route(r'/user/<username:\w+>', handler=user_posts, name='username'),
    webapp2.Route(r'/blog/newpost', handler=new_blog_post),
    webapp2.Route(r'/dice', handler=dice)
], debug=True)