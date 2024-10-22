import os

from dotenv import load_dotenv

load_dotenv()

FLASK_DEBUG = os.environ.get("FLASK_DEBUG")
<<<<<<< HEAD
SECRET_KEY = os.environ.get("SECRET_KEY")
=======
SECRET_KEY = os.environ.get("SECRET_KEY")
>>>>>>> b3a7ade (updated changes to app.py)
