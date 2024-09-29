from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
DATABASE = "dictionary.db"

#connecting to the database
def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        connection.row_factory = sqlite3.Row
        return connection
    except Error as e:
        print(e)
    return None

#checking if user is logged in
def is_logged_in():
    return 'user_id' in session # confirming to system that user is logged in, session important to specific feautures.

#to render home
@app.route('/')
def render_homepage():
    return render_template('home.html', logged_in=is_logged_in())

#to go to the dictionary page 
@app.route('/dictionary')
def render_dictionary():
    catergory_id = request.args.get('catergory_id')
    search_query = request.args.get('search', '').strip() #search function available
    con = create_connection(DATABASE)
    cur = con.cursor()

    cur.execute("SELECT * FROM catergories")
    catergories = cur.fetchall()

    words = []
    if catergory_id:
        cur.execute('SELECT * FROM dict WHERE catergory_id = ?', (catergory_id,))
        words = cur.fetchall()
    elif search_query:
        cur.execute("""
            SELECT * FROM dict 
            WHERE maori LIKE ? OR english LIKE ?""", 
            ('%' + search_query + '%', '%' + search_query + '%')) #used to allow search and matching words that are english or maori 
        words = cur.fetchall()

    con.close()
    return render_template('dictionary.html', catergories=catergories, words=words, catergory_id=catergory_id, search_query=search_query)
#pass parameters to be used in individual catergories

#for navigating to specific word details when pressed
@app.route('/word/<int:word_id>')
def render_word_detail(word_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute('SELECT * FROM dict WHERE id = ?', (word_id,)) #connects to specific word based on id
    word = cur.fetchone() 
    con.close()
    if word:
        return render_template('word_detail.html', word=word) 
    else:
        return "Word not found", 404 #giving error incase user tries to input the incorrect number id

#for deleting word, creating deletion specific to word using id of word
@app.route('/delete_entry/<int:id>', methods=['POST'])
def delete_entry(id):
    if 'user_id' not in session or session['role_id'] != 2:
        return redirect('/login?error=Unauthorized') #incase student somehow gets into deletion stage
    con = create_connection(DATABASE)
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM dict WHERE id = ?", (id,))
        con.commit()
    except Error as e:
        print("Error deleting word: {}".format(e)) #incase of error
    con.close()
    return redirect('/dictionary')

# login function 
@app.route('/login', methods=['GET', 'POST'])
def render_login_page():
    if is_logged_in():
        return redirect('/') #incase user is already logged in
    if request.method == 'POST':
        email = request.form['email'].strip().lower() 
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute("SELECT account_id, first_name, password, role_id FROM users WHERE email = ?", (email,)) #getting all users from database to compare to login
        user_data = cur.fetchone()
        con.close()
        if user_data and bcrypt.check_password_hash(user_data['password'], password): #checking if user details are correct
            session['user_id'] = user_data['account_id']
            session['email'] = email
            session['firstname'] = user_data['first_name']
            session['role_id'] = user_data['role_id']
            return redirect('/') 
        return redirect("/login?error=Invalid") #incase incorrect password or email
    return render_template('login.html', logged_in=is_logged_in())

#logout function
@app.route('/logout')
def logout():
    session.clear() #logs out
    return redirect('/login?message=See+you+next+time!') 

#register function
@app.route('/signup', methods=['GET', 'POST'])
def render_signup_page():
    if request.method == 'POST': #allows user input for name, user, email etc.
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].lower().strip()
        password = request.form['password']
        role_id = request.form['role_id']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8') #generates password hash
        con = create_connection(DATABASE)
        query = "INSERT INTO users (first_name, last_name, username, email, password, role_id) VALUES (?, ?, ?, ?, ?, ?)"
        cur = con.cursor()
        try:
            cur.execute(query, (first_name, last_name, username, email, hashed_password, role_id))
            con.commit()
            return redirect('/login?message=Signup successful! Please log in.')
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email is already used') #incase email is already used
        except Exception as e:
            print("An error occurred: {}".format(e))
            return redirect('/signup?error=An unexpected error occurred')#error handling
        con.close()
    roles = [{"role_id": 1, "role_name": "student"}, {"role_id": 2, "role_name": "teacher"}] 
    return render_template('signup.html', logged_in=is_logged_in(), roles=roles)

#feedback function
@app.route('/feedback', methods=['GET', 'POST'])
def render_feedback():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        message = request.form['message'].strip()
        con = create_connection(DATABASE)
        if con:
            cur = con.cursor()
            try:
                if name and email and message:
                    cur.execute("INSERT INTO feedback (name, email, message) VALUES (?, ?, ?)", 
                                (name, email, message)) #inserting feedback into database
                    con.commit()
                    return redirect('/feedback?message=Feedback submitted successfully!')
                return redirect('/feedback?error=All fields are required.')
            except Exception as e:
                print("Error: {}".format(e))
                return redirect('/feedback?error=An unexpected error occurred')
    return render_template('feedback.html', logged_in=is_logged_in())

#account page if logged in
@app.route('/account')
def render_account():
    if not is_logged_in():
        return redirect('/login?message=You+need+to+be+logged+in.')
    return render_template('account.html', logged_in=True, user=session)

#if user is logged in, enables the ability to navigate to in account to get role features
@app.route('/admin', methods=['GET'])
def render_admin():
    if not is_logged_in():
        return redirect('/login?message=Need+to+be+logged+in.')
    if session.get('role_id') != 2:
        return redirect('/')

    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute("SELECT * FROM catergories")
    category_list = cur.fetchall()

    return render_template("admin.html", logged_in=is_logged_in(), categories=category_list)

#allows teachers to add catergory
@app.route('/add_category', methods=['POST'])
def add_category():
    category_name = request.form['name']
    con = create_connection(DATABASE)
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO catergories (catergory_name) VALUES (?)", (category_name,))
        con.commit()
    except Error as e:
        print("Error adding category: {}".format(e))
    con.close()
    return redirect('/admin')

#allows teachers to delete catergory
@app.route('/delete_category', methods=['POST'])
def delete_category():
    category_id = request.form['cat_id']
    con = create_connection(DATABASE)
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM catergories WHERE catergory_id = ?", (category_id,)) #delete catergory in database
        con.commit()
    except Error as e:
        print("Error deleting category: {}".format(e))
    con.close()
    return redirect('/admin')

#allows teachers to add word
@app.route('/add_word', methods=['POST'])
def add_word():
    maori = request.form['maori'].strip()
    english = request.form['english'].strip()
    catergory_id = request.form['cat_id']
    definition = request.form['definition'].strip()
    level = request.form['level']
    image_path = request.form['image_path'].strip() or 'noimage'
    username = session.get('username')

    con = create_connection(DATABASE)
    cur = con.cursor()
    try:
        if maori and english and catergory_id and definition and level:
            cur.execute("""
                INSERT INTO dict (maori, english, catergory_id, definition, level, image_path, username)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (maori, english, catergory_id, definition, level, image_path, username)) #insert new word into database
            con.commit()
    except Error as e:
        print("Error adding word: {}".format(e))
    finally:
        con.close()

    return redirect('/admin')

#allows teachers to delete word
@app.route('/delete_word', methods=['POST'])
def delete_word():
    english_word = request.form['english_word'].strip()
    con = create_connection(DATABASE)
    cur = con.cursor()
    try:
        if english_word:
            cur.execute("DELETE FROM dict WHERE english = ?", (english_word,))
            con.commit()
    except Error as e:
        print("Error deleting word: {}".format(e))
    con.close()
    return redirect('/admin')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81)
