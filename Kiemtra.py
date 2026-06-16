import os
import pandas as pd
import time
import joblib
from sklearn.preprocessing import MinMaxScaler

# Khai báo các cột và mapping protocol
columns = ['ip_source', 'ip_destination', 'duration', 'protocol_type', 
           'src_bytes', 'dst_bytes', 'count', 'serror_rate', 'rerror_rate']

pmap = {'ICMP': 0, 'TCP': 1, 'UDP': 2}

# Load mô hình
model = joblib.load("random_forest_model_balanced1.pkl")

# Hàm xử lý và lưu dữ liệu
def process_and_update(input_file, output_file):
    try:
        # Đọc dữ liệu từ file nguồn
        df = pd.read_csv(input_file, names=columns, low_memory=False)
        df = df.drop(0)  # Bỏ dòng tiêu đề nếu có

        # Map protocol và đặt giá trị mặc định cho duration
        df['protocol_type'] = df['protocol_type'].map(pmap)
        df['duration'] = 0

        # Lưu trữ các địa chỉ IP
        dfip = df[['ip_source', 'ip_destination']].copy()

        # Xóa các cột không cần thiết
        df.drop(['ip_source', 'ip_destination'], axis=1, inplace=True)

        # Xử lý giá trị thiếu
        df.fillna(0, inplace=True)

        # Chuyển đổi kiểu dữ liệu
        df['src_bytes'] = df['src_bytes'].astype('int64')
        df['dst_bytes'] = df['dst_bytes'].astype('int64')
        df['count'] = df['count'].astype('int64')
        df['serror_rate'] = df['serror_rate'].astype('float64')
        df['rerror_rate'] = df['rerror_rate'].astype('float64')

        # Chuẩn hóa dữ liệu
        sc = MinMaxScaler()
        X = sc.fit_transform(df)

        # Dự đoán
        predictions = model.predict(X)

        # Thêm cột kết quả dự đoán và các cột IP
        df['prediction'] = predictions
        df.insert(1, 'ip_source', dfip['ip_source'])
        df.insert(2, 'ip_destination', dfip['ip_destination'])
        pmap2={0:'ICMP',1:'TCP',2:'UDP'}
        df['protocol_type']=df['protocol_type'].map(pmap2)
        
        # Nếu file `done.csv` đã tồn tại, chỉ thêm bản ghi mới
        if os.path.exists(output_file):
            done_df = pd.read_csv(output_file)

            # Lọc các bản ghi mới (chưa xuất hiện trong `done.csv`)
            new_records = df[~df.isin(done_df).all(axis=1)]
            updated_df = pd.concat([done_df, new_records], ignore_index=True)
        else:
            updated_df = df

        # Ghi kết quả vào file output
        updated_df.to_csv(output_file, index=False)
        print(f"Updated {output_file} successfully.")

    except Exception as e:
        print(f"Error during processing: {e}")

# Đường dẫn file
input_file = "network_connections.csv"
output_file = "done.csv"

# Biến theo dõi thời gian sửa đổi file
last_modified_time = None

# Vòng lặp thực hiện mỗi 15 giây
while True:
    try:
        # Kiểm tra thời gian sửa đổi của file nguồn
        current_modified_time = os.path.getmtime(input_file)

        # Nếu file thay đổi, thực hiện xử lý
        if last_modified_time is None or current_modified_time != last_modified_time:
            print(f"Detected change in {input_file}. Processing...")
            process_and_update(input_file, output_file)
            last_modified_time = current_modified_time

    except FileNotFoundError:
        print(f"File {input_file} not found. Retrying in 15 seconds...")
    
    # Chờ 15 giây trước khi kiểm tra lại
    time.sleep(15)
