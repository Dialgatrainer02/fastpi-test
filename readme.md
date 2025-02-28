# fast-api test

## setup 
```sh
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## running
```sh
fastapi dev api
```
or use the run box in vscode

## testing
```sh
pytest api
```
or use thw testing tab in vscode

## documentation
run the api and go to http://127.0.0.1/docs for the openapi spec