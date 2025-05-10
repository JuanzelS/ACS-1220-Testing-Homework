import os
from unittest import TestCase
from datetime import date
from books_app.extensions import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.auth.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)
    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)

def logout(client):
    return client.get('/logout', follow_redirects=True)

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
    
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()
        
        # Make sure no user is logged in at the start of each test
        with self.app.session_transaction() as session:
            session.clear()
    
    def test_signup(self):
        """
        Test the signup route.
        
        This test ensures that:
        1. A new user can be created through the signup form
        2. The user is correctly added to the database
        """
        post_data = {
            'username': 'new_user',
            'password': 'new_password'
        }
        response = self.app.post('/signup', data=post_data, follow_redirects=True)
        
        # Check that the user now exists in the database
        self.assertEqual(response.status_code, 200)
        user = User.query.filter_by(username='new_user').first()
        self.assertIsNotNone(user)
    
    def test_signup_existing_user(self):
        """
        Test signup with an existing username.
        
        This test ensures that:
        1. A user cannot sign up with a username that already exists
        2. The appropriate error message is displayed
        """
        # Create a user
        create_user()
        
        # Make a POST request to /signup with the same username
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        response = self.app.post('/signup', data=post_data, follow_redirects=True)
        
        # Check that the form is displayed again with an error message
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn('That username is taken', response_text)
    
    def test_login_correct_password(self):
        """
        Test login with correct credentials.
        
        This test ensures that:
        1. A user can log in with the correct username and password
        2. After login, the login button is no longer visible
        """
        # Create a user
        create_user()
        
        # Make a POST request to /login
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        response = self.app.post('/login', data=post_data, follow_redirects=True)
        
        # Check that the "login" button is not displayed on the homepage
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn('Log In', response_text)
        self.assertIn('Log Out', response_text)  # Check that logout is visible instead
    
    def test_login_nonexistent_user(self):
        """
        Test login with a nonexistent user.
        
        This test ensures that:
        1. A user cannot log in with a username that doesn't exist
        2. The appropriate error message is displayed
        """
        # Make a POST request to /login with a nonexistent user
        post_data = {
            'username': 'nonexistent_user',
            'password': 'password'
        }
        response = self.app.post('/login', data=post_data, follow_redirects=True)
        
        # Check that the login form is displayed again with an error message
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn('No user with that username', response_text)
    
    def test_login_incorrect_password(self):
        """
        Test login with incorrect password.
        
        This test ensures that:
        1. A user cannot log in with an incorrect password
        2. The appropriate error message is displayed
        """
        # Create a user
        create_user()
        
        # Make a POST request to /login with incorrect password
        post_data = {
            'username': 'me1',
            'password': 'wrong_password'
        }
        response = self.app.post('/login', data=post_data, follow_redirects=True)
        
        # Check that the login form is displayed again with an error message
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        
        # Fixed assertion to match actual HTML output
        self.assertIn('Password doesn&#39;t match', response_text)
    
    def test_logout(self):
        """
        Test the logout route.
        
        This test ensures that:
        1. A logged-in user can log out
        2. After logout, the login button is visible again
        """
        # Create a user
        create_user()
        
        # Log the user in
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        login_response = self.app.post('/login', data=post_data, follow_redirects=True)
        login_text = login_response.get_data(as_text=True)
        self.assertIn('Log Out', login_text)  # Verify user is logged in
        
        # Make a GET request to /logout
        response = self.app.get('/logout', follow_redirects=True)
        
        # Check that the "login" button appears on the homepage
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn('Log In', response_text)