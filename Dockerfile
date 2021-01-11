FROM python:3.7 as builder

WORKDIR /app
ADD requirements.txt /app
RUN mkdir /app/lib && pip install -r requirements.txt -t /app/lib/

FROM gcr.io/distroless/python3-debian10

WORKDIR /app

COPY --from=builder /app/lib/ /usr/local/lib/python3.7/site-packages
COPY . /app

ENV PYTHONPATH=/usr/local/lib/python3.7/site-packages:/app
