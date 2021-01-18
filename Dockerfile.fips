FROM python:3.7 as builder

WORKDIR /app
ADD requirements.txt /app
RUN mkdir /app/lib && pip install -r requirements.txt -t /app/lib/

FROM amazonlinux:2.0.20201218.1

ENV OPENSSL_FIPS=1
ENV PYTHONPATH=/usr/local/lib/python3.7/site-packages:/app

WORKDIR /app

RUN yum install -y dracut-fips openssl python3 && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY --from=builder /app/lib/ /usr/local/lib/python3.7/site-packages
COPY . /app
