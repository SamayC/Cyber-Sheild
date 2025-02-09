from flask import Flask, render_template
from phishing import phishing  # Correct import for phishing blueprint
from ids_ml_gradio import ids_ml_gradio  # Correct import for ids_ml_gradio blueprint
from web import web  # Import web blueprint from web.py

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(phishing, url_prefix='/phishing')
app.register_blueprint(ids_ml_gradio, url_prefix='/predict')
app.register_blueprint(web, url_prefix='/web')  # Registering web blueprint with '/web' prefix

# Route for the home page
@app.route('/home')
def home():
    return render_template('home.html')  # Render the home page with options

if __name__ == '__main__':
    app.run(debug=True)
