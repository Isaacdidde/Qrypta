from dotenv import load_dotenv
load_dotenv()   # 👈 THIS LINE IS THE FIX

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
