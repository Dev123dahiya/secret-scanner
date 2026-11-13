FROM python:3.12-slim
WORKDIR /app
COPY secretscan ./secretscan
COPY data ./data
RUN useradd --create-home appuser
USER appuser
ENTRYPOINT ["python", "-m", "secretscan"]
CMD ["demo"]
