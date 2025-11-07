# make sure venv active
./venv/Scripts/activate
./venv/Scripts/mitmproxy -s save_flow.py --listen-host 0.0.0.0 -p 8080
