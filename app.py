from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home_page.html')

@app.route('/signup')
def signup():
    return render_template('sign_up_page.html')

if __name__ == '__main__':
    app.run(debug=True)

    

