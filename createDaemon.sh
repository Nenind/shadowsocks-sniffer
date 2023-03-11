#!/bin/bash

touch /etc/systemd/system/$(pwd).service

cat > /etc/systemd/system/$(pwd).service <<EOF 
[Unit]
Description="Best bot 4ever!"

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/$(pwd)
VIRTUAL_ENV=/home/ubuntu/$(pwd)/venv
Environment=PATH=$VIRTUAL_ENV/bin:$PATH
ExecStart=/home/ubuntu/$(pwd)/venv/bin/python main.py

[Install]
WantedBy=multi-user.target
EOF


python3 -m venv venv
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

systemctl daemon-reload
systemctl start $(pwd).service
systemctl enable $(pwd).service
systemctl status $(pwd).service