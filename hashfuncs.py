import random
import string
import hashlib
import hmac

SECRET = '255fd2d12ca5d9f380f795782e36ee19'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    split_hash = h.split(',')
    pw_hash = split_hash[0]
    pw_salt = split_hash[1]

    if pw_hash == hashlib.sha256(name + pw + pw_salt).hexdigest():
        return True
    else:
        return False