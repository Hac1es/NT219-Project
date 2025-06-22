#!/bin/bash
source ../../venv/bin/activate

# ========================
# ⚙️ CONFIG
# ========================
BANK_NAME="ACB"
APP_MODULE="interbankAPI:app"
HOST="0.0.0.0"
PORT=443
CERT="../Certificate/${BANK_NAME}.crt"
KEY="../Certificate/${BANK_NAME}.key"
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
