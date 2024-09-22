#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
from datetime import datetime
import base64
import hashlib

app = Flask(__name__)

# Define the flag
FLAG = "CTF{Header_Hunter}"


# Step 1: Requires correct Date header and specific User-Agent
@app.route("/")
def index():
    expected_date = datetime.now().strftime("%d%m%Y")
    user_agent = request.headers.get("User-Agent", "")

    if request.headers.get("Date") == expected_date and "ctf-browser" in user_agent:
        # Step 2: Return base64-encoded string with the next instructions
        message = (
            "\nGood job!"
            "\nUse an algorithm from the 90s that turns the word 'challenge' into a 32-character hash. The same algorithm is used in many checksum tools."
            "\nHINT: Use curl with a JSON body to POST the hash to /final"
        )
        encoded_message = base64.b64encode(message.encode()).decode("utf-8")
        return jsonify({"Message": f"Good job! Decode this: {encoded_message}"})
    else:
        return (
            jsonify(
                {
                    "Message": "Sometimes servers like to see a little extra information in your request headers.",
                    "HINT": f"Expected User-Agent 'ctf-browser'. The current Date is $(date +%d%m%Y).",
                }
            ),
            403,
        )


# Step 3: Requires solving the hash challenge
@app.route("/final", methods=["POST"])
def final():
    data = request.get_json()
    if not data or "hash" not in data:
        return jsonify({"message": "Missing hash"}), 400

    correct_hash = "0e6177f6115fb9763435da24bd1babc7"
    if data["hash"] == correct_hash:
        return jsonify({"flag": FLAG})
    else:
        return jsonify({"message": "Incorrect hash!"}), 403


# Step 4: Check if the provided flag is correct
@app.route("/check", methods=["POST"])
def check_flag():
    data = request.get_json()
    if not data or "Flag" not in data:
        return jsonify({"message": "Missing flag"}), 400

    provided_flag = data["Flag"]
    if provided_flag == FLAG:
        return jsonify(
            {"message": "Congratulations! You've submitted the correct flag!"}
        )
    else:
        return jsonify({"message": "Incorrect flag!"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443)
