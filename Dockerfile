# Build wheels once; the runtime image has no pip and never reaches PyPI.
FROM docker.io/library/python:3.15-alpine AS build
WORKDIR /src
COPY pyproject.toml ./
COPY netbox_snmp_sync ./netbox_snmp_sync
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM docker.io/library/python:3.15-alpine
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/*.whl \
 && rm -rf /wheels \
 && pip uninstall -y pip \
 && adduser -D -H -u 10001 snmpsync
USER 10001
ENTRYPOINT ["netbox-snmp-sync"]
CMD ["--config", "/config/config.yaml", "--mode", "report"]
