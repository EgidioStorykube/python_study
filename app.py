from flask import Flask, render_template, request, url_for, redirect, session, abort
# , jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user
import hashlib
from flask_login import current_user
from flask import render_template
from easyprocess import EasyProcess
import datetime
from datetime import timedelta
import pyshorteners
from static.test import test
import random
import string


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SECRET_KEY"] = "abc"
db = SQLAlchemy()

login_manager = LoginManager()
login_manager.init_app(app)


class Users(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(250), unique=True, nullable=False)
	password = db.Column(db.String(250), nullable=False)
	role = db.Column(db.String(250), default='user')
 
 
class Url(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	ip_address = db.Column(db.String(250), nullable=False)
	ip_status = db.Column(db.Boolean, default=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

	def serialize(self):
		return {
			'id': self.id,
			'ip_address': self.ip_address,
			'ip_status': self.ip_status,
			'user_id': self.user_id
		}
  
  
class Todo(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(250), nullable=False)
	description = db.Column(db.String(250), nullable=False)
	expiration = db.Column(db.DateTime, default=None)
	expired = db.Column(db.Boolean, default=False)
	status = db.Column(db.Boolean, default=False)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

	def serialize(self):
		return {
			'id': self.id,
			'title': self.title,
			'description': self.description,
			'expiration': self.expiration,
			'expired': self.expired,
			'status': self.status,
			'user_id': self.user_id
		}

db.init_app(app)

with app.app_context():
	db.create_all()


# Create a default admin user
	existing_admin_user = Users.query.filter_by(role='admin').first()
	if not existing_admin_user:
		admin_username = "admin"
		admin_password = "admin"  # Assicurati di usare una password sicura
		hashed_admin_password = hashlib.sha256(admin_password.encode('utf-8')).hexdigest()
		admin_user = Users(username=admin_username, password=hashed_admin_password, role='admin')
		db.session.add(admin_user)
		db.session.commit()
  
  
# Create a default admin url	
	existing_admin_url = Url.query.filter_by(user_id=1).first()
	if not existing_admin_user:
		ip_address = 'https://www.google.com'
		url = Url(ip_address=ip_address, user_id=1)
		db.session.add(url)
		db.session.commit()
  
# Create a default admin todo
	existing_admin_todo = Todo.query.filter_by(user_id=1).first()
	if not existing_admin_todo:
		title = 'Learn Python and Flask in a web application.'
		description = 'Use python and Flask in a web application.'
		
		todo = Todo(title=title, description=description, user_id=1)
		todo1 = Todo(title='learn js', description=description, expiration=datetime.datetime.now() + timedelta(days=1), status=True, user_id=1)
		todo2 = Todo(title='learn php', description=description, expiration=datetime.datetime.now(), status=False, user_id=1)
		todo3 = Todo(title='learn html', description=description, expiration=datetime.datetime.now() + timedelta(days=2), status=True, user_id=1)
		todo4 = Todo(title='learn css', description=description, expiration=datetime.datetime.now() + timedelta(days=2), status=False, user_id=1)
		todo5 = Todo(title='learn twig', description=description, expiration=datetime.datetime.now() + timedelta(days=2), status=True, user_id=1)
  
		todos = [todo, todo1, todo2, todo3, todo4, todo5]
		db.session.add_all(todos)
		db.session.commit()


@login_manager.user_loader
def loader_user(user_id):
	return Users.query.get(user_id)


# Register and login routes
@app.route("/register", methods=["GET", "POST"])
def register():
	if request.method == "POST":
		username = request.form.get("username")
		password = request.form.get("password")
		hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
		user = Users(username=username, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		return redirect(url_for("login"))
	return render_template("sign_up.html")


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username = request.form.get("username")
		password = request.form.get("password")
		user = Users.query.filter_by(username=username).first()

		if user and user.password == hashlib.sha256(password.encode('utf-8')).hexdigest():
			login_user(user)
			return redirect(url_for("home"))
	return render_template("login.html")

# Logout route
@app.route("/logout")
def logout():
	logout_user()
	session.clear()
	return redirect(url_for("home"))

# Home route
@app.route("/")
def home():
	return render_template("home.html", user=current_user)


# Check if the user is admin
def is_admin():
	if current_user.role == 'admin':
		pass
	else:
		return abort(401)


@app.route("/admin")
def admin_dashboard():
	is_admin()
	users = Users.query.all()  # Get all users from the database
	return render_template("admin_dashboard.html", username=current_user.username, role=current_user.role, users=users)


@app.route("/admin/delete/<user_id>")
def delete_user(user_id):
	is_admin()
	user_to_delete = Users.query.get(user_id)
	db.session.delete(user_to_delete)
	db.session.commit()
	return redirect(url_for("admin_dashboard"))


@app.route("/admin/change_role/<user_id>", methods=["GET", "POST"]) 
def change_role(user_id):
	is_admin()
	user_to_update = Users.query.get(user_id)
	if request.method == "POST":
		new_role = request.form.get("role")
		user_to_update.role = new_role
		db.session.commit()
		return redirect(url_for("admin_dashboard"))
	return redirect(url_for("admin_dashboard"))

 
def ping(ip):
    ping="ssh %s date;exit"%(ip) # test ssh alive or
    ping="curl -IL %s"%(ip)      # test if http alive
    response=len(EasyProcess(ping).call(timeout=2).stdout)
    return response != 0 #integer 0 if no response in 2 seconds


@app.route("/ip_address_monitoring_tool/<user_id>")
def get_urls_by_user_id(user_id):
	check_authorization(str(current_user.id), user_id)

	urls = Url.query.filter_by(user_id=user_id).all()

	# Update the ip_status for each url
	for url in urls:
		url.ip_status = ping(url.ip_address)
		db.session.commit()

	serialized_urls = [url.serialize() for url in urls]
	return render_template("ip_address_monitoring_tool.html", urls=serialized_urls)


@app.route("/add_ip_address", methods=["GET", "POST"])
def add_ip_address():
	if request.method == "POST":
		ip_address = request.form.get("ip_address")
		user_id = current_user.id
		url = Url(ip_address=ip_address, user_id=user_id)
		db.session.add(url)
		db.session.commit()
		return redirect(url_for("get_urls_by_user_id", user_id=user_id))
	return render_template("add_ip_address.html")


@app.route("/update_ip_address/<url_id>", methods=["GET", "POST"])
def update_ip_address(url_id):
	url = Url.query.get(url_id)
	check_authorization(current_user.id, url.user_id)

	if request.method == "POST":
		url.ip_address = request.form.get("ip_address_update")
		db.session.commit()
  
		return redirect(url_for("get_urls_by_user_id", user_id=current_user.id))


@app.route("/delete_ip_address/<url_id>")
def delete_ip_address(url_id):
	url = Url.query.get(url_id)
	check_authorization(current_user.id, url.user_id)

	db.session.delete(url)
	db.session.commit()
	return redirect(url_for("get_urls_by_user_id", user_id=current_user.id))


@app.route("/todo_list_tool/<user_id>")
def get_todo_list_by_user_id(user_id):
	check_authorization(str(current_user.id), user_id)

	todos = Todo.query.filter_by(user_id=user_id).order_by(Todo.expiration.is_(None), Todo.expiration).all()

	# Update the ip_status for each url
	for todo in todos:
		if todo.expiration is not None:
			if todo.expiration < datetime.datetime.now():
				todo.expired = True
				db.session.commit()
			else:
				todo.expired = False
				db.session.commit()

	serialized_todos = [todo.serialize() for todo in todos]
	return render_template("todo_list_tool.html", todos=serialized_todos)


@app.route("/todo_list_tool/add/<user_id>", methods=["GET", "POST"])
def add_todo_list_by_user_id(user_id):
	check_authorization(str(current_user.id), user_id)

	if request.method == "POST":
		title = request.form.get("todo_title")
		description = request.form.get("todo_description")
		expiration = request.form.get("todo_expiration")
		if expiration == "":
			expiration = None
		else:
			date_format = "%Y-%m-%d"
			expiration = datetime.datetime.strptime(expiration, date_format)
		todo = Todo(title=title, description=description, expiration=expiration, user_id=user_id)
		db.session.add(todo)
		db.session.commit()
		return redirect(url_for("get_todo_list_by_user_id", user_id=user_id))
	return render_template("todo_add.html")


@app.route("/todo_list_tool/<todo_id>/update", methods=["GET", "POST"])
def update_todo_list_by_id(todo_id):
	todo = Todo.query.get(todo_id)
	check_authorization(current_user.id, todo.user_id)

	if request.method == "POST":
		todo.title = request.form.get("todo_title_update")
		todo.description = request.form.get("todo_description_update")
		expiration = request.form.get("todo_expiration_update")
		if expiration == "":
			todo.expiration = None
		else:
			date_format = "%Y-%m-%d"
			todo.expiration = datetime.datetime.strptime(expiration, date_format)
   
		db.session.commit()
		return redirect(url_for("get_todo_list_by_user_id", user_id=todo.user_id))
	
	return render_template("todo_update.html", todo=todo)


@app.route("/todo_list_tool/<todo_id>/status_update")
def get_todo_list_by_id(todo_id):
	todo = Todo.query.get(todo_id)

	check_authorization(current_user.id, todo.user_id)

	todo.status = not todo.status
	db.session.commit()
 
	return redirect(url_for("get_todo_list_by_user_id", user_id=todo.user_id))


@app.route("/todo_list_tool/<todo_id>/delete")
def delete_todo_list_by_id(todo_id):
	todo = Todo.query.get(todo_id)

	check_authorization(current_user.id, todo.user_id)

	db.session.delete(todo)
	db.session.commit()
 
	return redirect(url_for("get_todo_list_by_user_id", user_id=todo.user_id))


@app.route("/url_shortener", methods=["GET", "POST"])
def url_shortener():
	check_authorization()
	short_url = None
	if request.method == "POST":
		try:
			long_url = request.form.get("long_url")
			type_tiny = pyshorteners.Shortener()
			short_url = type_tiny.tinyurl.short(long_url)
		except:
			short_url_error = "Invalid URL"
			return render_template("url_shortener.html", short_url_error=short_url_error)
	
	if short_url is not None:
		return render_template("url_shortener.html", short_url=short_url)

	return render_template("url_shortener.html")


def replace_multiple_newlines(text):
    lines = text.split('\n')
    lines = [line for line in lines if line.strip()]
    return len(lines)
  
  
@app.route('/words_counter',methods=['GET','POST'])
def count():
	check_authorization()

	if request.method == 'POST':
		text = request.form['text']
		
		words = len(text.split())
		
		paras = replace_multiple_newlines(text)
		text = text.replace('\r','')
		text = text.replace('\n','')
		chars = len(text)
		unique_words = len(set(text.split()))

		return render_template('words_counter.html', origin_text=request.form['text'], words=words, paras=paras, chars=chars, test_text=test.lorem_text(), unique_words=unique_words) 

	return render_template('words_counter.html',test_text=test.lorem_text())  
  
  
@app.route('/gen_password',methods=['GET','POST'])
def gen_password():
	check_authorization()

	if request.method == 'POST':
		minpasslen = 8
		maxpasslen = 30
		min_num_gen = 1
		max_num_gen = 10
  
		session['passlen'] = request.form.get('passlen')
		passlen = int(session['passlen'])
		session['num_gen'] = request.form.get('num_gen')
		num_gen = int(session['num_gen'])
		if passlen<minpasslen:
			return render_template('gen_password.html', mess=f'At least create a {minpasslen} digit password...')
		if passlen>maxpasslen:
			return render_template('gen_password.html', mess=f'Can Create a max {maxpasslen} digit password...')
		if num_gen<min_num_gen:
			return render_template('gen_password.html', mess=f'At least create a {min_num_gen} password...')
		if num_gen>max_num_gen:
			return render_template('gen_password.html', mess=f'Can Create a max {max_num_gen} password...')
 
		# Preserve the selected options
		session['include_spaces'] = request.form.get('includespaces')
		session['include_numbers'] = request.form.get('includenumbers')
		session['include_special_chars'] = request.form.get('includespecialchars')
		session['include_uppercase_letters'] = request.form.get('includeuppercaseletters')
		include_spaces = session.get('include_spaces')
		include_numbers = session.get('include_numbers')
		include_special_chars = session.get('include_special_chars')
		include_uppercase_letters = session.get('include_uppercase_letters')
		# Create the character sets
		lowercase_letters = string.ascii_lowercase # abcdefghijklmnopqrstuvwxyz
		uppercase_letters = string.ascii_uppercase # ABCDEFGHIJKLMNOPQRSTUVWXYZ
		digits = string.digits # 0123456789
		special_chars = string.punctuation # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
		# print(include_spaces,include_numbers,include_special_chars,include_uppercase_letters)
		char_sets = [lowercase_letters] # Initialize the list of character sets
		# Add character sets based on the parameters
		if include_spaces=='on':	
			char_sets.append(' ') # Add a space to the list of character sets
		if include_numbers=='on': 
			char_sets.append(digits) # Add digits to the list of character sets
		if include_special_chars=='on':
			char_sets.append(special_chars) # Add special characters to the list of character sets
		if include_uppercase_letters=='on':
			char_sets.append(uppercase_letters) # Add uppercase letters to the list of character sets
		gen_passwords = []
		for i in range(num_gen):
			# Combine the character sets
			all_chars = ''.join(char_sets) # Combine the character sets into a single string
			gen_password = random.choices(all_chars, k=passlen) # Generate the password
			gen_password = ''.join(gen_password) # Convert the list of characters into a string
			gen_passwords.append(gen_password)
	
		return render_template('gen_password.html', gen_passwords=gen_passwords, num_gen=num_gen, passlen=passlen, include_spaces=include_spaces, include_numbers=include_numbers, include_special_chars=include_special_chars, include_uppercase_letters=include_uppercase_letters)
  
	return render_template('gen_password.html')
  
  
def check_authorization(current_id=None, id=None):
  
	if current_user.is_anonymous:
		return abort(401)  # Unauthorized		
	if id != current_id:
		return abort(401)  # Unauthorized
	else:
		pass


@app.errorhandler(401)
def unauthorized_error(error):
	return render_template('error_401.html'), 401


if __name__ == "__main__":
	app.run()
