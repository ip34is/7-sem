# Навчальний стенд із НАВМИСНО ВРАЗЛИВИМ застосунком.
# Використовується лише всередині ізольованої мережі docker compose.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN mkdir -p /app/storage \
 && printf 'Публічний файл стенда.\n' > /app/storage/readme.txt \
 && printf 'Синтетичний внутрішній документ.\n' > /app/storage/internal.txt \
 && python seed.py

ENV VULNAPP_DB=/tmp/vulnapp.db
EXPOSE 5000 5001

CMD ["python", "app.py"]
