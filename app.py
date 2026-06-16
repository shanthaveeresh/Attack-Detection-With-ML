from flask import Flask, render_template, request, redirect, url_for
from scapy.all import get_if_list
import os
import psutil
import pandas as pd
import signal
import subprocess
import time
import sys

app = Flask(__name__)

# Biến toàn cục để lưu giao diện mạng được chọn
selected_interface = None

# Trang chính với danh sách giao diện
@app.route("/")
def index():
    # Lấy thông tin các giao diện mạng
    net_interfaces = psutil.net_if_stats()

    # Lưu tên giao diện mạng vào list_interface
    list_interface = list(net_interfaces.keys())
    return render_template("index.html", interfaces=list_interface, selected_interface=selected_interface)

# Xử lý khi người dùng chọn giao diện mạng
@app.route("/set_interface", methods=["POST"])
def set_interface():
    global selected_interface
    selected_interface = request.form.get("interface")
    return redirect(url_for("index"))

# Bắt đầu thu thập dữ liệu (chỉ hiển thị giao diện để xác nhận)
@app.route("/start_capture", methods=["POST"])
def start_capture():
    if selected_interface:
        # Kiểm tra nếu đã chọn giao diện
        os.system(f"python packet_capture.py {selected_interface} &")
        return f"Đã bắt đầu thu thập gói tin trên giao diện: {selected_interface}"

    else:
        return "Vui lòng chọn một giao diện trước!"

@app.route("/results")
def show_results():   
        subprocess.run(["python3", "Kiemtra.py"])      


@app.route("/view")
def show_view():
    try:
        
        # Kiểm tra nếu tệp CSV tồn tại
        if not os.path.isfile("done.csv"):
            return render_template("results.html", error="Không tìm thấy dữ liệu phân tích. Hãy thu thập gói tin trước.")
        
        # Đọc dữ liệu từ file CSV
        df = pd.read_csv("done.csv", on_bad_lines="skip")  # Xử lý lỗi dòng không hợp lệ
        results = df.to_dict(orient="records")
    except Exception as e:
        results = None
        error_message = f"Không thể đọc tệp dữ liệu: {e}"
        return render_template("results.html", error=error_message)

    return render_template("results.html", results=results)



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)



