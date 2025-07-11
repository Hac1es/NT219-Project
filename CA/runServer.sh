#!/bin/bash
source ../venv/bin/activate

# ========================
# ⚙️ CONFIG
# ========================
APP_MODULE="server:app"
HOST="0.0.0.0"
PORT=443
CERT="sbv.org.crt"
KEY="sbv.org.key"
IP_ADDR=$(hostname -I | awk '{print $1}')  # lấy IP đầu tiên trong dãy IP nội bộ

# ========================
# ✅ Check files
# ========================
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Thiếu $CERT hoặc $KEY. Đảm bảo bạn đã tạo chứng chỉ SSL đúng chỗ."
  exit 1
fi

# ========================
# 🚀 Run server
# ========================
echo "Đang chạy FastAPI server tại https://$IP_ADDR:$PORT"
uvicorn $APP_MODULE --host $HOST --port $PORT --ssl-certfile $CERT --ssl-keyfile $KEY
