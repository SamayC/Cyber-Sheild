import xgboost as xgb
import numpy as np
from flask import Blueprint, render_template, request
from _2_scale_transform import transform_new_input

# Define Blueprint
ids_ml_gradio = Blueprint('ids_ml_gradio', __name__, template_folder='templates')

# Load the model
model = xgb.Booster()
model.load_model("m3_xg_boost.model")

# User input prediction function

# User input prediction function
def user_input_predict(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13):
    # Preprocessing input
    user_input = [[x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13]]
    user_input = np.array(user_input)
    user_input = transform_new_input(user_input)
    user_input = xgb.DMatrix(user_input)

    # Prediction
    user_input_result = model.predict(user_input)
    user_input_result = np.argmax(user_input_result)

    result_msg = ""
    result_msg_info = ""

    if user_input_result == 0:
        result_msg = "NORMAL, No possibility of attack."
        result_msg_info = "You are safe!"
    elif user_input_result == 1:
        result_msg = "Higher Possibility of BLACKHOLE attack."
        result_msg_info = (
            "Information= Meaning: BLACKHOLE attacks occur when a router deletes all messages it is supposed to forward.\n"
            "Impacts: A Blackhole Attack causes network disruption, data loss, Denial of Service (DoS), routing table manipulation, performance degradation, and resource wastage.\n"
            "Countermeasures: Using Intrusion Detection Systems (IDS), secure routing protocols, traffic filtering, blackhole routing to discard malicious traffic, regular software updates, and anomaly detection to monitor abnormal behavior."
        )
    elif user_input_result == 2:
        result_msg = "Higher Possibility of TCP-SYN attack."
        result_msg_info = (
            "Information: A SYN flood (half-open attack) is a type of denial-of-service (DDoS) attack that aims to make a server unavailable to legitimate traffic by consuming all available server resources.\n"
            "Impacts: A TCP-SYN attack causes service disruption, Denial of Service (DoS), resource exhaustion, performance degradation, and potential system crashes by overwhelming server resources.\n"
            "Countermeasures: Include SYN cookies, rate limiting, firewalls & IDS, TCP handshake validation, load balancers, and connection timeouts to mitigate the attack’s impact."
        )
    elif user_input_result == 3:
        result_msg = "Higher Possibility of PORTSCAN attack."
        result_msg_info = (
            "Information: A port scan sends client requests to a range of server port addresses on a host, with the goal of finding an active port and exploiting a known vulnerability of that service.\n"
            "Impacts: It can lead to unauthorized access, data theft, network reconnaissance, and targeted attacks.\n"
            "Countermeasures: Using firewalls, intrusion detection systems (IDS), port filtering, randomizing ports, and rate limiting to detect and block scan attempts."
        )
    elif user_input_result == 4:
        result_msg = "Higher Possibility of DIVERSION attack."
        result_msg_info = (
            "Information: Diversion/Social engineering is an attack vector that manipulates people into breaking normal security procedures to gain unauthorized access to systems or networks.\n"
            "Impacts: It leads to data theft, service disruption, and unauthorized access.\n"
            "Countermeasures: DNSSEC, secure routing protocols, traffic encryption, intrusion detection systems (IDS), and regular network monitoring to detect and prevent unauthorized redirections."
        )
    else:
        result_msg = "Try Again"
        result_msg_info = "Choose different values."

    return result_msg, result_msg_info

# Define Blueprint routes
@ids_ml_gradio.route('/')
def home():
    return render_template('ids.html')

@ids_ml_gradio.route('/predict', methods=['POST'])
@ids_ml_gradio.route('/predict', methods=['POST'])
def predict():
    try:
        # Retrieve inputs from the form
        x1 = request.form.get('x1', type=int)
        x2 = request.form.get('x2', type=int)
        x3 = request.form.get('x3', type=int)
        x4 = request.form.get('x4', type=int)
        x5 = request.form.get('x5', type=int)
        x6 = request.form.get('x6', type=int)
        x7 = request.form.get('x7', type=int)
        x8 = request.form.get('x8', type=int)
        x9 = request.form.get('x9', type=int)
        x10 = request.form.get('x10', type=int)
        x11 = request.form.get('x11', type=int)
        x12 = request.form.get('x12', type=int)
        x13 = request.form.get('x13', type=int)

        # Validate inputs
        inputs = [x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13]
        if any(value is None for value in inputs):
            return render_template('idsresult.html', 
                                   result_msg="Invalid Input", 
                                   result_msg_info="Please enter all required values for prediction.")

        # Log the inputs for debugging
        print(f"Inputs: {inputs}")

        # Call prediction function
        result_msg, result_msg_info = user_input_predict(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13)

        # Log the result for debugging
        print(f"Prediction: {result_msg}")
        
        # Render result page
        return render_template('idsresult.html', result_msg=result_msg, result_msg_info=result_msg_info)
    except Exception as e:
        # Log the error for debugging
        print(f"Error: {e}")
        return render_template('idsresult.html', 
                               result_msg="Error", 
                               result_msg_info="An error occurred. Please try again.")
