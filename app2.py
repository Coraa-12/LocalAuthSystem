from werkzeug.security import generate_password_hash
from app import db, User, app

def convert_plain_text_passwords():
    users = User.query.all()
    if not users:
        print('No users found in the database.')
        return

    converted_count = 0
    for user in users:
        if not user.password.startswith('pbkdf2:sha256:'):
            hashed_password = generate_password_hash(user.password, method='pbkdf2:sha256')
            user.password = hashed_password
            db.session.commit()
            print(f'Converted password for user: {user.username}')
            converted_count += 1

    if converted_count == 0:
        print('No plain text passwords found to convert.')
    else:
        print(f'Converted passwords for {converted_count} users.')

if __name__ == '__main__':
    with app.app_context():
        convert_plain_text_passwords()