## This is used to load the app in the local host environment or we can call a application runner

from dotenv import load_dotenv
load_dotenv()   # 👈 THIS LINE IS THE FIX

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
