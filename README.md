# Job Portal
A web-based job portal application where users can register, log in, create job listings, apply for jobs, and manage their profiles. It also includes an admin panel where job listings and user activities can be managed.

1. Clone the Repository
Clone this repository to your local machine using the following command:

git clone https://github.com/rar-rahul/Flask-Assignment.git

2. Install Dependency
cd Flask-Assignment

# Technologies Used
Flask: Web framework for building the application
Flask-SQLAlchemy: ORM for database management
Flask-Bcrypt: For password hashing and security
Flask-Login: User session management and authentication
MySQL: Database (used via pymysql)
Flask-WTF: Forms handling and validation
Werkzeug: File handling (used for saving resumes and supporting documents)

# Features
User registration and login
Job listing creation and management
Job applications with file upload support (resume and supporting documents)
Admin panel for approving/rejecting jobs and proposals, and managing users
User profile management
Search and filter job listings by keywords, category, and location

# pip install

Flask
Flask-SQLAlchemy
Flask-Bcrypt
Flask-Login
Flask-WTF
pymysql

3. Run the Development Server
python main.py   
python -m venv venv  -- Activate the virtual environment:


4. Open the Application
Now, you can open the application in your browser at http://localhost:5000. You should see the homepage of the Freelancer Portal.

5. # For admin panal
# Admin Credentials
By default, the first registered user is assigned as the admin role.
You can log in as the admin with the first user created using the registration form.

