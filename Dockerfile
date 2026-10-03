FROM python:3.12-slim

RUN mkdir -p /workspace && chown 1000:1000 /workspace

WORKDIR /workspace
COPY goldmansachs/runner.py /app/runner.py
COPY defence/app/runner.py /app/defence_runner.py

# OpenShell executes the workload as UID 1000. COPY from the root build stage
# otherwise leaves the handler root-owned and unreadable to that identity.
RUN chmod 0444 /app/runner.py /app/defence_runner.py

CMD ["sleep", "infinity"]
