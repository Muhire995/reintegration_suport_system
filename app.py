from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask import Flask, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the upload folder and allowed extensions
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database connection configuration
def create_connection():
    connection = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='reintegration_support'
        )
    except Error as e:
        print(f"Error: '{e}'")
    return connection

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/opportunities')
def opportunities():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch job opportunities from the database
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM job_opportunities")
    jobs = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('opportunities.html', jobs=jobs)


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('login'))

@app.route('/user_status')
def user_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor(dictionary=True)

    # Fetching appointments along with the username and status
    appointments_query = """
        SELECT a.id, a.appointment_date, a.therapist_name, a.notes, a.status, a.created_at, u.username
        FROM mental_health_appointments a
        JOIN users u ON a.user_id = u.id
        WHERE a.user_id = %s
    """
    cursor.execute(appointments_query, (session['user_id'],))
    appointments = cursor.fetchall()

    # Fetch job opportunities
    job_opportunities_query = """
        SELECT title, company, description, application_url, created_at
        FROM job_opportunities
    """
    cursor.execute(job_opportunities_query)
    job_opportunities = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template('user_status.html', appointments=appointments, job_opportunities=job_opportunities)

@app.route('/appointments')
def appointments():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = create_connection()
    cursor = connection.cursor(dictionary=True)

    # Fetching appointments along with the username and status
    query = """
        SELECT a.id, a.appointment_date, a.therapist_name, a.notes, a.status, a.created_at, u.username
        FROM mental_health_appointments a
        JOIN users u ON a.user_id = u.id
        WHERE a.user_id = %s
    """
    cursor.execute(query, (session['user_id'],))

    appointments = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('appointments.html', appointments=appointments)


@app.route('/update_status', methods=['POST'])
def update_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    appointment_id = request.form.get('appointment_id')
    new_status = request.form.get('status')

    # Validate inputs
    if not appointment_id or not new_status:
        return redirect(url_for('appointments'))

    connection = create_connection()
    cursor = connection.cursor()

    try:
        # Update the status in the database
        query = """
            UPDATE mental_health_appointments
            SET status = %s
            WHERE id = %s
        """
        cursor.execute(query, (new_status, appointment_id))
        connection.commit()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('appointments'))


@app.route('/register_activity', methods=['GET', 'POST'])
def register_activity():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = request.form.get('date')
        image = request.files.get('image')

        # Validate inputs
        if not title or not description or not date:
            return redirect(url_for('register_activity'))

        # Save image if provided
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        connection = create_connection()
        cursor = connection.cursor()

        try:
            # Insert the new activity into the database
            query = """
                INSERT INTO community_activities (title, description, date, image)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (title, description, date, image_filename))
            connection.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('user_dashboard'))  # Redirect to the activities list page
    return render_template('register_activity.html')

@app.route('/community_activities', methods=['GET'])
def community_activities():
    if 'user_id' not in session:
        return redirect(url_for('login'))


    connection = create_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        # Fetch all activities from the community_activities table
        cursor.execute("SELECT * FROM community_activities ORDER BY created_at DESC")
        activities = cursor.fetchall()
    except Error as e:
        print(f"Error: '{e}'")
        flash('An error occurred while retrieving community activities.', 'error')
        activities = []
    finally:
        cursor.close()
        connection.close()

    return render_template('social.html', activities=activities)



# @app.route('/user_dashboard')
# def user_dashboard():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))  # Redirect to login if the user is not logged in
#
#     return render_template('user.html')  # Renders the user dashboard page


@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' in session and session['role'] == 'user':
        return render_template('user.html')
    else:
        return redirect(url_for('login'))
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    def validate_username(self, username):
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username.data,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email.data,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

@app.route('/job_opportunities', methods=['GET', 'POST'])
def job_opportunities():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        company = request.form['company']
        description = request.form['description']
        application_url = request.form['application_url']

        connection = create_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO job_opportunities (title, company, description, application_url) VALUES (%s, %s, %s, %s)",
                (title, company, description, application_url)
            )
            connection.commit()
            flash('Job opportunity added successfully!', 'success')
        except Error as e:
            print(f"Error: '{e}'")
            flash('An error occurred while adding the job opportunity.', 'error')
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('job_opportunities'))

    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM job_opportunities")
    jobs = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('job_opportunities.html', jobs=jobs)

@app.route('/mental_health_appointments', methods=['GET', 'POST'])
def mental_health_appointments():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        appointment_date = request.form['appointment_date']
        therapist_name = request.form['therapist_name']
        notes = request.form['notes']

        connection = create_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO mental_health_appointments (user_id, appointment_date, therapist_name, notes) VALUES (%s, %s, %s, %s)",
                (user_id, appointment_date, therapist_name, notes)
            )
            connection.commit()
            flash('Mental health appointment scheduled successfully!', 'success')
        except Error as e:
            print(f"Error: '{e}'")
            flash('An error occurred while scheduling the appointment.', 'error')
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('mental_health_appointments'))

    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM mental_health_appointments WHERE user_id = %s", (session['user_id'],))
    appointments = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('mental_health_appointments.html', appointments=appointments)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)
        role = 'user'

        connection = create_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                (username, email, password, role)
            )
            connection.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except Error as e:
            flash(f"An error occurred: {str(e)}", 'error')
        finally:
            cursor.close()
            connection.close()
    return render_template('register.html', form=form)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#
#         connection = create_connection()
#         cursor = connection.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cursor.fetchone()
#         cursor.close()
#         connection.close()
#
#         if user and check_password_hash(user['password'], password):
#             session['user_id'] = user['id']
#             session['role'] = user['role']
#             return redirect(url_for('dashboard'))
#         else:
#             return render_template('login.html', error="Invalid credentials. Please try again.")
#
#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']

            if user['role'] == 'admin':
                return redirect(url_for('dashboard'))
            elif user['role'] == 'user':
                return redirect(url_for('user_dashboard'))
            else:
                # Handle unexpected role
                return render_template('login.html', error="Invalid user role. Please contact support.")
        else:
            return render_template('login.html', error="Invalid credentials. Please try again.")

    return render_template('login.html')

# @app.route('/dashboard')
# def dashboard():
#     if 'user_id' in session:
#         return render_template('dashboard.html')
#     return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session and session['role'] == 'admin':
        return render_template('dashboard.html')
    else:
        return redirect(url_for('login'))

@app.route('/add_resource', methods=['GET', 'POST'])
def add_resource():
    if 'user_id' in session and session['role'] == 'admin':
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            url = request.form['url']

            connection = create_connection()
            cursor = connection.cursor()

            try:
                cursor.execute(
                    "INSERT INTO resources (title, description, url) VALUES (%s, %s, %s)",
                    (title, description, url)
                )
                connection.commit()
                cursor.close()
                connection.close()
                return redirect(url_for('resources'))
            except Error as e:
                print(f"Error: '{e}'")
                cursor.close()
                connection.close()
                return render_template('add_resource.html',
                                       error="An error occurred while adding the resource. Please try again.")

        return render_template('add_resource.html')
    else:
        return redirect(url_for('login'))

@app.route('/resources')
def resources():
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM resources")
    resources = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('resources.html', resources=resources)

@app.route('/forums')
def forums():
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM forums")
    forums = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('forums.html', forums=forums)

@app.route('/forum/<int:forum_id>')
def forum(forum_id):
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM posts WHERE forum_id = %s", (forum_id,))
    posts = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('social.html', posts=posts, forum_id=forum_id)


@app.route('/add_progress', methods=['GET', 'POST'])
def add_progress():
    if 'user_id' in session:
        if request.method == 'POST':
            description = request.form['description']
            status = request.form['status']
            user_id = session['user_id']

            # Get the current time for created_at
            from datetime import datetime
            created_at = datetime.now()

            connection = create_connection()
            cursor = connection.cursor()

            try:
                cursor.execute(
                    "INSERT INTO progress (user_id, description, status, created_at) VALUES (%s, %s, %s, %s)",
                    (user_id, description, status, created_at)
                )
                connection.commit()
                cursor.close()
                connection.close()
                return redirect(url_for('progress'))
            except Error as e:
                print(f"Error: '{e}'")
                cursor.close()
                connection.close()
                return render_template('add_progress.html', error="An error occurred while adding the progress entry. Please try again.")

        return render_template('add_progress.html')
    else:
        return redirect(url_for('login'))



@app.route('/progress')
def progress():
    if 'user_id' in session:
        user_id = session['user_id']
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM progress WHERE user_id = %s", (user_id,))
        progress_entries = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('progress.html', progress_entries=progress_entries)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)