from app import db, app
from sqlalchemy import text

# Add the reset_token and profile_picture columns to the user table
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text('ALTER TABLE user ADD COLUMN profile_picture VARCHAR(200)'))