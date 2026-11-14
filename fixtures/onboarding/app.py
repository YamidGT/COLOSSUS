from pathlib import Path

from flask import Flask

app = Flask(__name__)
Path("synthetic-state.txt").write_text("initialized")


@app.get("/")
def index():
    return "COLOSSUS owned setup fixture: " + Path("synthetic-state.txt").read_text()


if __name__ == "__main__":
    app.run(debug=True)
