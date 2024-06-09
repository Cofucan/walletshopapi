# WalletShop API

To use this API,

Clone the repo

```shell
git clone <repo-link>
```

Create a virtual environment (at least Python 3.11)

```shell
python3 -m venv venv
```

Activate the venv

```shell
source venv/bin/activate
```

Install requirements

```shell
pip install -r requirements.txt
```

Copy the .env_example file to a .env file

```shell
cp .env_example .env
```

Setup your mysql database and update the .env file with your database credentials

Run the migrations

```shell
alembic upgrade head
```

Run the app

```shell
uvicorn main:app --reload
```
