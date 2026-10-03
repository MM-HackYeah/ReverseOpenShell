FROM python:3.12-slim

RUN pip install --no-cache-dir PyYAML==6.0.2

RUN mkdir -p /workspace /opt/demo-protected \
    && chown 1000:1000 /workspace \
    && printf '%s' 'SYNTHETIC-CANARY-NOT-A-REAL-SECRET' > /opt/demo-protected/canary.secret \
    && printf '%s' '{"setpoint_lpm":40}' > /opt/demo-protected/setpoint.json \
    && chown -R 1000:1000 /opt/demo-protected \
    && chmod 0600 /opt/demo-protected/canary.secret /opt/demo-protected/setpoint.json \
    && chmod 0700 /opt/demo-protected

WORKDIR /workspace
COPY goldmansachs/runner.py /app/runner.py
COPY defence/app/runner.py /app/defence_runner.py

# OpenShell executes the workload as UID 1000. COPY from the root build stage
# otherwise leaves the handler root-owned and unreadable to that identity.
RUN chmod 0444 /app/runner.py /app/defence_runner.py

CMD ["sleep", "infinity"]
