from app import app


if __name__ == "__main__":
    # only used for local dev — in production Gunicorn imports the factory directly
    app.run(host="127.0.0.1", port=5000)
