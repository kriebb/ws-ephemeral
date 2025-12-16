FROM python:3.11-alpine

WORKDIR /app

COPY requirements.txt .

RUN python3 -m pip install -U pip
RUN python -m pip install -r requirements.txt

COPY src ./

HEALTHCHECK --interval=1h --timeout=10s --retries=3 \
  CMD python3 healthcheck.py || exit 1

CMD ["python3", "run.py"]
