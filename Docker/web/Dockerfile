FROM python:3.11.4-slim-buster

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    default-libmysqlclient-dev \
    libmariadb-dev \
    gcc \
    nano \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install nltk && \
    python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords');"

COPY . .

EXPOSE 8000
ENV DJANGO_SETTINGS_MODULE=spam_mail_project.settings

CMD ["sh", "-c", "python manage.py makemigrations && python manage.py migrate && python manage.py collectstatic --noinput && python manage.py runserver 0.0.0.0:8000"]