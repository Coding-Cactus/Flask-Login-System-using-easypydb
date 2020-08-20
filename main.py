import flask, hashlib, uuid, os
from easypydb import DB

# flasky stuff
app = flask.Flask(__name__)
app.secret_key = os.getenv('secretKey')
session = flask.session


# db stuff
dbToken = os.getenv('dbToken')
userDB = DB('userDB', dbToken)


# function for salting and hashing the password
def hash_password(password):
	salt = uuid.uuid4().hex
	return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
    
# function to compare the hashed password stored in teh db with the inputted password
def check_password(hashed_password, user_password):
	password, salt = hashed_password.split(':')
	return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()



#---------------------------------------------------------------------
#								Routes
#---------------------------------------------------------------------

# main route (just returns index page)
@app.route('/')
def main():
	return flask.render_template('index.html', session=session)


# returns the page with the sign up form
@app.route('/signup')
def getSignup():
	return flask.render_template('signup.html')

# this is called when they click submit on the form on the signup page
@app.route('/signup', methods=['POST'])
def signup():
	# get the info from the form
	username = flask.request.form['username']
	password1 = flask.request.form['password1']
	password2 = flask.request.form['password2']
	
	# checks if there is already someone with the username
	if username in userDB.data:
		return flask.render_template('signup.html', error='Already a user with that name.')

	# checks if the password is too small
	elif len(password1) < 6:
		return flask.render_template('signup.html', error='Password needs to be at least 6 characters long')

	# checks to make sure the two entered passwords are the same
	elif password1 != password2:
		return flask.render_template('signup.html', error='Passwords did not match')
	
	# if eveything has been doen right then it adds them and their hashed password to the db
	else:
		# add the user with their username and hashed password to the db
		userDB[username] = hash_password(password1)
		
		# adds the user to the flask session
		session['user'] = username
		session.modified = True
		return flask.redirect('/')


# get the page with the log in form
@app.route('/login')
def getLogin():
	return flask.render_template('login.html')


# this is called when the form on the log in page is submitted
@app.route('/login', methods=['POST'])
def login():
	# gets the info from teh form
	username = flask.request.form['username']
	password = flask.request.form['password']

	# checks if it is an actual username
	if username not in userDB.data:
		return flask.render_template('login.html', error='Incorrect username or password.')
	
	# calls the function which comapres the hashed password stored in the db to the inputted password
	elif check_password(userDB[username], password):
		# adds the user to the flask session
		session['user'] = username
		session.modified = True
		return flask.redirect('/')
	
	# if the password is wrong, sends them back to the form
	else:
		return flask.render_template('login.html', error='Incorrect username or password.')

# removes the user from the flask session
@app.route('/logout')
def logout():
	session.pop('user', None)
	return flask.redirect('/')


# runs the server
app.run('0.0.0.0')