from flask import Flask,render_template,redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from werkzeug.utils import secure_filename

#configuration
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:root@localhost/freelance_db"
app.secret_key = "this-is-my-secreste-key"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
##

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'jpg', 'png'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

    # job_applications = db.relationship('Application', backref='user', lazy=True)
    # job_listings = db.relationship('JobListing', backref='user', lazy=True)

class JobListing(db.Model):
    __tablename__ = 'job_listings'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    pay_rate = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # user = db.relationship('User', backref=db.backref('job_listings', lazy=True))

class Application(db.Model):
    __tablename__ = 'proposals'

    id = db.Column(db.Integer, primary_key=True)
    cover_letter = db.Column(db.Text, nullable=False)
    resume = db.Column(db.String(120), nullable=False) 
    supporting_documents = db.Column(db.String(120))  
    job_id = db.Column(db.Integer, db.ForeignKey('job_listings.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
   # created_at = db.Column(db.DateTime, default=datetime.utcnow)
    job = db.relationship('JobListing', backref=db.backref('proposals', lazy=True))
    user = db.relationship('User', backref=db.backref('proposals', lazy=True))

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



#Job creation and listing

@app.route('/job-listing',methods=['GET'])
def jobListing():
   
    keywords = request.args.get('keywords', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    sort_by = request.args.get('sort_by', 'date_posted')

    # Build the query based on the parameters
    query = JobListing.query

    if keywords:
        query = query.filter(JobListing.title.contains(keywords) | JobListing.description.contains(keywords))
    
    if category:
        query = query.filter(JobListing.category == category)
    
    if location:
        query = query.filter(JobListing.location.contains(location))

    jobs = query.all()


    #job_listings = JobListing.query.all()  
    return render_template('joblist.html', job_listings=jobs)


@app.route("/job-creation",methods=["GET", "POST"])
@login_required
def create_job():

    if request.method == "POST":
        # Get data from form
        title = request.form['title']
        description = request.form['description']
        pay_rate = request.form['pay_rate']
        location = request.form['location']
        category = request.form['category']

        # Create a new job listing and add it to the database
        new_job = JobListing(
            title=title,
            description=description,
            pay_rate=float(pay_rate),
            location=location,
            category=category,
            user_id=current_user.id  
        )

        db.session.add(new_job)
        db.session.commit()

        print(new_job)

        flash('Job created successfully!', 'success')
        return redirect(url_for('jobListing')) 

    return render_template('job_create_form.html')


@app.route('/apply/<int:job_id>', methods=["GET", "POST"])
@login_required
def apply_for_job(job_id):
    job = JobListing.query.get_or_404(job_id)

    if request.method == 'POST':
        # Get form data
        cover_letter = request.form['cover_letter']

        # Get resume file
        resume = request.files['resume']
        if resume and allowed_file(resume.filename):
            resume_filename = secure_filename(resume.filename)
            resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume_filename)
            resume.save(resume_path)

        # supporting documents 
        supporting_documents = request.files.getlist('supporting_documents[]')
        supporting_docs_paths = []
        for doc in supporting_documents:
            if doc and allowed_file(doc.filename):
                doc_filename = secure_filename(doc.filename)
                doc_path = os.path.join(app.config['UPLOAD_FOLDER'], doc_filename)
                doc.save(doc_path)
                supporting_docs_paths.append(doc_path)

        # Create a new proposal entry
        new_proposal = Application(
            cover_letter=cover_letter,
            resume=resume_filename,
            supporting_documents=";".join(supporting_docs_paths) if supporting_docs_paths else None,
            job_id=job.id,
            user_id=current_user.id
        )

        db.session.add(new_proposal)
        db.session.commit()

        flash('Your application has been submitted!', 'success')
        return redirect(url_for('jobListing'))


    return render_template('job_apply_form.html', job=job)


# Profile section
@app.route('/profile/', methods=["GET", "POST"])
def profile():
    user = current_user  

    # Fetch the user's job applications, job listings, and payment history
    job_applications = Application.query.filter_by(user_id=user.id).all()
    job_listings = JobListing.query.filter_by(user_id=user.id).all()
   
    return render_template('profile.html', user=user, 
                           job_applications=job_applications, 
                           job_listings=job_listings,
                           )



@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user

    if request.method == 'POST':
        
        user.name = request.form['name']
        user.email = request.form['email']
        
        db.session.commit()

        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)


@app.route('/profile/job_applications')
@login_required
def job_applications():
    user = current_user
    applications = Application.query.filter_by(user_id=user.id).all()
    return render_template('job_applications.html', applications=applications)

@app.route('/profile/job_listings')
@login_required
def job_listings():
    user = current_user
    listings = JobListing.query.filter_by(user_id=user.id).all()
    return render_template('job_listings.html', listings=listings)




if __name__ == "__main__":
    #Run the app in debug mode to auto-reload
    app.run(debug=True)