FROM python:3.11-slim

ENV LANG C.UTF-8
ENV USER root
ENV HOME /cloudfail
ENV DEBIAN_FRONTEND noninteractive

COPY . $HOME

WORKDIR $HOME

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "cloudfail.py"]
