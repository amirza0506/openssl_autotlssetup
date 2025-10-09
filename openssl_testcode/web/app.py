from flask import Flask, render_template_string, request
import ctypes, os, binascii

lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "../lib/libcryptoapi.so"))
# prototypes
lib.crypto_init.restype = ctypes.c_int
lib.crypto_cleanup.restype = None
lib.sign_hybrid.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t)]
lib.sign_hybrid.restype = ctypes.c_int
lib.free_buf.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

app = Flask(__name__)
lib.crypto_init()

HTML = """
<!doctype html>
<title>Crypto GUI</title>
<h1>Sign (hybrid) demo</h1>
<form method=post>
  <textarea name=msg rows=4 cols=60>{{msg}}</textarea><br>
  <input type=submit value="Sign hybrid">
</form>
{% if sig %}
<h2>Signature (hex)</h2>
<pre>{{sig}}</pre>
{% endif %}
"""

@app.route("/", methods=["GET","POST"])
def index():
    sig_hex = None
    msg = "hello world"
    if request.method == "POST":
        msg = request.form.get("msg","")
        msg_b = msg.encode()
        out_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        out_len = ctypes.c_size_t(0)
        res = lib.sign_hybrid(msg_b, len(msg_b), ctypes.byref(out_ptr), ctypes.byref(out_len))
        if res == 0:
            # copy bytes
            buf = ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_ubyte * out_len.value)).contents
            sig_hex = binascii.hexlify(bytes(buf)).decode()
            lib.free_buf(out_ptr)
        else:
            sig_hex = "error"
    return render_template_string(HTML, sig=sig_hex, msg=msg)

@app.route("/shutdown")
def shutdown():
    lib.crypto_cleanup()
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
    return "shutting down"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
