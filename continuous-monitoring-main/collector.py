# from flask import Flask, request

# app = Flask(__name__)

# @app.route("/alert", methods=["POST"])
# def alert():
#     print("\n🚨 FAILED LOGIN EVENT RECEIVED 🚨")
#     print(request.json)
#     return "ok"

# app.run(host="0.0.0.0", port=5000)

#--------------------------v1-----------------------

from flask import Flask, request

app = Flask(__name__)

@app.route("/alert", methods=["POST"])
def alert():
    data = request.json
    event_type = data.get("event", "UNKNOWN")

    print(f"\n🚨 {event_type} EVENT RECEIVED 🚨")
    print(data)

    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
