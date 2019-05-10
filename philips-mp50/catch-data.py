import json
import sqlite3
from klein import Klein

db_filename = "./data.db"

connection = sqlite3.connect(db_filename, detect_types=sqlite3.PARSE_DECLTYPES)

def adapt_json(data):
    return (json.dumps(data, sort_keys=True)).encode()

def convert_json(blob):
    return json.loads(blob.decode())

def setup_db():
    sqlite3.register_adapter(dict, adapt_json)
    sqlite3.register_adapter(list, adapt_json)
    sqlite3.register_adapter(tuple, adapt_json)
    sqlite3.register_converter('JSON', convert_json)
    connection.execute("""
    CREATE TABLE IF NOT EXISTS  (
        data JSON,
    )
    """)

class DataStore(object):
    app = Klein()

    def __init__(self):
        self._items = {}

    @app.route('/')
    def items(self, request):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(self._items)

    @app.route('/', methods=['POST'])
    def do_post(request):
        content = json.loads(request.content.read())
        response = json.dumps(dict(the_data=content), indent=4)
        return response

    @app.route('/<string:name>', methods=['GET'])
    def get_item(self, request, name):
        request.setHeader('Content-Type', 'application/json')
        return json.dumps(self._items.get(name))


if __name__ == '__main__':
    store = ItemStore()
    store.app.run('localhost', 8080)
