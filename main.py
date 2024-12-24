from flask import Flask,render_template,redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:root@localhost/user_db"
app.secret_key = "this-is-my-secreste-key"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")


# Create all the tables 
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Home route
@app.route("/")
def home():
    return render_template('index.html')

@app.route("/register",methods=["GET", "POST"])
def register():

     if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        #hash password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You Have Successfully Registered with US!', 'success')
        return redirect(url_for('login'))
    
     return render_template('register.html')

#Login route 
@app.route("/login",methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            flash('Login Successful', 'success')
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/job-listing')
def jobListing():
    return render_template('joblist.html')





if __name__ == "__main__":
    #Run the app in debug mode to auto-reload
    app.run(debug=True)