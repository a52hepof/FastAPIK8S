# pull official base image
#FROM python:3.8.11-slim-buster
FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8
# create directory for the app user
RUN mkdir -p /home/app

# create the app user
RUN addgroup --system app && adduser --system --group app

# create the appropriate directories
ENV HOME=/home/app
ENV APP_HOME=/home/app/code
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV ENVIRONMENT prod


# install system dependencies
RUN apt-get update \
  && apt-get -y install netcat gcc libpq-dev sqlite3 libsqlite3-dev\
  && apt-get clean

# install python dependencies
RUN pip3 install --upgrade pip
RUN pip3 install -U setuptools
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

# add app
COPY . .

# chown all the files to the app user
RUN chown -R app:app $APP_HOME

# change to the app user
USER app

# run gunicorn
# CMD gunicorn --bind 0.0.0.0:5000 main:app -k uvicorn.workers.UvicornWorker
CMD uvicorn main:app --host 0.0.0.0 --port 8081