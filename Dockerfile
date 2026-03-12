FROM python:3.12-alpine

WORKDIR /tmp

COPY app.py requirements.txt index.html ./

EXPOSE 3000

RUN apk update && apk --no-cache add openssl bash curl &&\
    chmod +x app.py &&\
    pip install -r requirements.txt
    
CMD ["python3", "app.py"]
