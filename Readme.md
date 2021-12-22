1. installation
```
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```
2. typical start
```
python app.py --config templates/rules/test_server_com.yaml
```
3. for remove old rules:
```
python app.py --config templates/rules/test_server_com.yaml --remove ip1,ip2,ip3
or
python app.py --config templates/rules/test_server_com.yaml --remove server_1_com,server_2_com,server_3_com
```
4. flush all rules
```
python app.py --config templates/rules/test_server_com.yaml --flush
```
5. for help
```
python app.py --help
```