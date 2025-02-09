from flask import Blueprint, request, render_template
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from feature import generate_data_set
from whois import whois
import whois.parser
from urllib.parse import urlparse
import warnings

warnings.filterwarnings('ignore')

# Create a Blueprint
phishing = Blueprint('phishing', __name__, template_folder='templates')

# Load the dataset
data = pd.read_csv("phishing.csv")
data = data.drop(['Index'], axis=1)  # Drop index column
X = data.drop(["class"], axis=1)
y = data["class"]

# Instantiate and fit the model
gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
gbc.fit(X, y)



@phishing.route("/", methods=["GET", "POST"])
def index():
    return render_template("phish.html", xx=-1)

@phishing.route("/predict", methods=["POST"])
def predict():
    if request.method == "POST":

        url = request.form["url"]
        x = np.array(generate_data_set(url)).reshape(1,30) 
        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('phish.html',xx =round(y_pro_non_phishing,2),url=url )
        # else:
        #     pred = "It is {0:.2f} % unsafe to go ".format(y_pro_non_phishing*100)
        #     return render_template('index.html',x =y_pro_non_phishing,url=url )
    return render_template("phish.html", xx =-1)


@phishing.route('/test', methods=['GET'])
def get_phish():
    return render_template('phish.html')