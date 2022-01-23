FROM python:3.9-slim-bullseye

WORKDIR /usr/src/app

RUN pip3 install --upgrade pip

COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY app .

RUN python3 init_sqlite.py
