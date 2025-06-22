import psycopg2
from getpass import getpass

passw = getpass("Get PostgreSQL password: ")

# Thông tin kết nối PostgreSQL
conn_info = {
    "host": "localhost",
    "port": 5432,
    "dbname": "msb_db",  
    "user": "postgres", 
    "password": f"{passw}"      
}

def get_credit_scores_by_name():
    try:
        conn = psycopg2.connect(**conn_info)
        cursor = conn.cursor()
        name = input("Input customer name: ").strip()
        # Truy vấn lấy CustomerID
        cursor.execute("SELECT CustomerID FROM Customer WHERE Name = %s", (name,))
        result = cursor.fetchone()

        if not result:
            print("Không tìm thấy khách hàng:", name)
            return

        customer_id = result[0]

        # Truy vấn bảng Data
        cursor.execute("""
            SELECT Spayment, Sutil, Slength, Screditmix,
                   Sinquiries, Sincomestability, Sbehaviorial
            FROM Data
            WHERE CustomerID = %s
        """, (customer_id,))
        data = cursor.fetchone()

        if data:
            print(f"Chỉ số tín dụng của '{name}':")
            fields = ["Spayment", "Sutil", "Slength", "Screditmix",
                      "Sinquiries", "Sincomestability", "Sbehaviorial"]
            for field, value in zip(fields, data):
                print(f"  {field}: {value}")
        else:
            print(f"Không có dữ liệu tín dụng cho khách hàng '{name}'")

        cursor.close()
        conn.close()

    except Exception as e:
        print("Lỗi kết nối/truy vấn:", e)


# Ví dụ dùng
get_credit_scores_by_name()
