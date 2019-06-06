from flask import Flask
import threading

class RestDelegate:
    def index(self):
        return
    def get(self):
        return
        
    def put(self):
        return

    def post(self):
        return

    def delete(self):
        return

app = Flask(__name__)

class MitmRest:
    def __init__(self, appName, delegate=None, ports=5000):
        global app
        self.app = app
        self.app.service = self
        self.delegate = delegate
        self.ports=ports
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True

    def start(self):
        self.thread.start()

    def run(self):
        self.app.run(host='0.0.0.0', port=self.ports)
    
    @app.route("/")
    def index():
        if(app.service.delegate is not None):
            return app.service.delegate.index()
        return ""

    @app.route("/post", methods=['POST'])
    def post():
        if(app.service.delegate is not None):
            return app.service.delegate.post()

    @app.route("/put", methods=['PUT'])
    def put():
        if(app.service.delegate is not None):
            return app.service.delegate.put()
      
    @app.route("/delete", methods=['DELETE'])
    def delete():
        if(app.service.delegate is not None):
            return app.service.delegate.delete()
